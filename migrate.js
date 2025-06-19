const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const Message = require('./models/Message');

async function migrateMessages() {
  try {
    await mongoose.connect(process.env.MONGO_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');

    const messages = await Message.find({ id: { $exists: false } });
    for (const msg of messages) {
      msg.id = uuidv4();
      await msg.save();
      console.log(`Updated message ${msg._id} with id ${msg.id}`);
    }
    console.log('Migration complete');
  } catch (err) {
    console.error('Migration error:', err);
  } finally {
    await mongoose.connection.close();
  }
}

migrateMessages();