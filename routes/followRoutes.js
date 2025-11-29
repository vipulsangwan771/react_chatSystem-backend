// routes/followRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const FollowRequest = require('../models/FollowRequest');
const verifyToken = require('../middleware/verifyToken');
const logger = require('../utils/logger');

// GET /api/followed-users
router.get('/followed-users', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('following', '_id name email');
    res.json({ data: { users: user.following } });
  } catch (error) {
    logger.error('Error fetching followed users', { error: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/follow-requests/incoming
router.get('/follow-requests/incoming', verifyToken, async (req, res) => {
  try {
    const requests = await FollowRequest.find({ to: req.user.id, status: 'pending' }).populate('from', '_id name email');
    res.json({ data: { requests: requests.map(req => ({ requestId: req._id.toString(), from: req.from })) } });
  } catch (error) {
    logger.error('Error fetching incoming requests', { error: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/follow/:userId
router.post('/follow/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;
  try {
    if (userId === req.user.id) return res.status(400).json({ message: 'Cannot follow yourself' });
    const existingRequest = await FollowRequest.findOne({ from: req.user.id, to: userId });
    if (existingRequest) return res.status(400).json({ message: 'Follow request already sent' });
    const followRequest = new FollowRequest({ from: req.user.id, to: userId });
    await followRequest.save();
    const sender = await User.findById(req.user.id).select('_id name email');
    const io = req.app.get('socketio');
    io.to(userId).emit('follow-request', { requestId: followRequest._id.toString(), from: sender });
    res.json({ message: 'Follow request sent' });
  } catch (error) {
    logger.error('Error sending follow request', { error: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/follow/:userId (unfollow)
router.delete('/follow/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;
  try {
    await User.findByIdAndUpdate(req.user.id, { $pull: { following: userId } });
    await User.findByIdAndUpdate(userId, { $pull: { followers: req.user.id } });
    res.json({ message: 'Unfollowed successfully' });
  } catch (error) {
    logger.error('Error unfollowing user', { error: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/follow-requests/accept/:requestId
router.post('/follow-requests/accept/:requestId', verifyToken, async (req, res) => {
  const { requestId } = req.params;
  try {
    const followRequest = await FollowRequest.findById(requestId);
    if (!followRequest || followRequest.to.toString() !== req.user.id) return res.status(404).json({ message: 'Request not found' });
    if (followRequest.status !== 'pending') return res.status(400).json({ message: 'Request already processed' });
    followRequest.status = 'accepted';
    await followRequest.save();
    await User.findByIdAndUpdate(followRequest.to, { $addToSet: { followers: followRequest.from } });
    await User.findByIdAndUpdate(followRequest.from, { $addToSet: { following: followRequest.to } });
    const user = await User.findById(followRequest.from).select('_id name email');
    const io = req.app.get('socketio');
    io.to(followRequest.from.toString()).emit('follow-accepted', { user });
    res.json({ data: { user } });
  } catch (error) {
    logger.error('Error accepting follow request', { error: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/follow-requests/reject/:requestId
router.post('/follow-requests/reject/:requestId', verifyToken, async (req, res) => {
  const { requestId } = req.params;
  try {
    const followRequest = await FollowRequest.findById(requestId);
    if (!followRequest || followRequest.to.toString() !== req.user.id) return res.status(404).json({ message: 'Request not found' });
    if (followRequest.status !== 'pending') return res.status(400).json({ message: 'Request already processed' });
    followRequest.status = 'rejected';
    await followRequest.save();
    res.json({ message: 'Request rejected' });
  } catch (error) {
    logger.error('Error rejecting follow request', { error: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/block/:userId
router.post('/block/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;
  try {
    if (userId === req.user.id) return res.status(400).json({ message: 'Cannot block yourself' });
    await User.findByIdAndUpdate(req.user.id, { $addToSet: { blocked: userId } });
    // Remove from following/followers if applicable
    await User.findByIdAndUpdate(req.user.id, { $pull: { following: userId } });
    await User.findByIdAndUpdate(userId, { $pull: { followers: req.user.id } });
    res.json({ message: 'User blocked' });
  } catch (error) {
    logger.error('Error blocking user', { error: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// For filter/search: GET /api/users/search?query=
router.get('/users/search', verifyToken, async (req, res) => {
  const { query } = req.query;
  try {
    const myUser = await User.findById(req.user.id).select('following blocked');
    const users = await User.find({
      name: { $regex: query, $options: 'i' },
      _id: { $ne: req.user.id, $nin: myUser.blocked },
      blocked: { $ne: req.user.id } // Users who haven't blocked me
    }).select('_id name email');

    const myFollowing = myUser.following.map(id => id.toString());
    const pendingRequests = await FollowRequest.find({ from: req.user.id, status: 'pending' }).select('to');
    const pendingIds = pendingRequests.map(r => r.to.toString());

    const enhancedUsers = users.map(u => {
      const uObj = u.toObject();
      uObj.isFollowing = myFollowing.includes(u._id.toString());
      uObj.isPending = pendingIds.includes(u._id.toString());
      return uObj;
    });

    res.json({ data: { users: enhancedUsers } });
  } catch (error) {
    logger.error('Error searching users', { error: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;