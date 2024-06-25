import discord
from discord.ext import commands
import requests
import hashlib
import aiohttp
import os

TOKEN = 'MTIwNTU1MDYwMjA2NzY0MDM1MA.GGj9ma.foK_6TUlKECYz6CmaFWdENi6A_uyByzbVf2ojM'
VIRUSTOTAL_API_KEY = '23996c735849699fe01ef40456d9f22033f69efc0da9a3bba06d6f39f5ebf0aa'

delete_message = False  # Configure this

intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'{bot.user.name} подключе!')


async def download_file(url, file_name):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            with open(file_name, 'wb') as file:
                while True:
                    chunk = await response.content.read(1024)
                    if not chunk:
                        break
                    file.write(chunk)


async def check_virus(file_path, message):
    with open(file_path, 'rb') as file:
        file_bytes = file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()

    url = 'https://www.virustotal.com/vtapi/v3/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            positives = json_response['positives']
            total = json_response['total']
            if positives > 0:
                threat_info = "\n".join([f"`{key} - {value['result']}`" for key, value in json_response['scans'].items() if value.get('detected')])
                embed = discord.Embed(title="⚠️ Обнаружены угрозы", description=threat_info, color=discord.Color.red())
                embed.set_footer(text=f"{positives}/{total} антивирусов обнаружило угрозу.")
                await message.reply(embed=embed)
            else:
                embed = discord.Embed(title="✅ Файл чист.", color=discord.Color.green())
                await message.reply(embed=embed)
        else:
            embed = discord.Embed(title="❗ Ошибка во время сканирования", color=discord.Color.red())
            await message.reply(embed=embed)
    else:
        embed = discord.Embed(title="❗ Ошибка во время сканирования", color=discord.Color.red())
        await message.reply(embed=embed)


@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    for attachment in message.attachments:
        file_name = attachment.filename
        file_url = attachment.url
        await download_file(file_url, file_name)
        await check_virus(file_name, message)
        os.remove(file_name)

    await bot.process_commands(message)


bot.run(TOKEN)