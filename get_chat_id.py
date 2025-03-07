import telebot

TOKEN = "7937058330:AAGGBmvKysHvEUqE5Sl5BPTVlNNd18o9YZ8"  # Ganti dengan token bot Anda
bot = telebot.TeleBot(TOKEN)

@bot.message_handler(func=lambda message: True)
def echo_all(message):
    print("Chat ID Anda:", message.chat.id)

bot.polling()
