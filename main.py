import discord
from discord import app_commands
import dotenv
import os
import vt
import queue
import aiohttp
import asyncio
import hashlib
from typing import Literal
import json
dotenv.load_dotenv()
intent = discord.Intents.default()
intent.message_content = True
discord_client = discord.Client(intents=intent)
cmdtree = app_commands.CommandTree(discord_client)
VT_API_KEY = os.environ["VT_APIKEY"]
DISCORD_API_TOKEN = os.environ["DISCORD_TOKEN"]
vt_client = vt.Client(VT_API_KEY)
taskqueue = queue.Queue()
check_count = 4
checkcount_hour = 20
setting = []

@discord_client.event
async def on_ready():
    global setting
    print(f"bot logged in as {discord_client.user}")
    await asyncio.ensure_future(main_loop())
    with open("./setting.json", "r") as f:
        setting = json.load(f)

@discord_client.event
async def on_message(content: discord.message.Message):
    global taskqueue
    global setting
    if content.channel in setting:
        return
    if content.attachments != [] and check_count >= 1:
        print("attachment found!")
        mes_embed = discord.Embed(title="ファイルをチェック中です...", description="※この結果は参考として使用してください。このBotをセキュリティソフトの代替として使用しないでください。")
        mes_embed.add_field(name="ファイルチェックには最大で5分以上かかります。", value="")
        await content.reply(embed=mes_embed)
        f : discord.Attachment = None
        for f in content.attachments:
            await f.save("./download_files/" + f.filename)
            if taskqueue.qsize() < 4:
                with open("./download_files/" + f.filename, "rb") as fi:
                    hash_res = await CheckHash(hashlib.sha256(fi.read()).hexdigest())
                    print(hash_res.__class__)
                print("File Check : " + f.filename)
                if hash_res["isEnable"] == False:
                    res = await CheckFile(f.filename)
                    (ret_embed, isdetect) = CreateEmbed("fileResult", res)
                    if isdetect:
                        await content.add_reaction("\N{No Entry Sign}")
                    else:
                        await content.add_reaction("\N{White Heavy Check Mark}")
                    await content.reply(embed=ret_embed)
                else:
                    (ret_embed, isdetect) = CreateEmbed("hashResult", hash_res)
                    if isdetect:
                        await content.add_reaction("\N{No Entry Sign}")
                    else:
                        await content.add_reaction("\N{White Heavy Check Mark}")
                    await content.reply(embed=ret_embed)
            else:
                print("can't check file : queue size is big")
        

def CreateEmbed(type : Literal["hashResult", "fileResult"], dic : dict) -> (discord.Embed, bool):
    if type == "hashResult":
        print(dic["response_code"])
        if dic["positives"] <= 0:
            embed = discord.Embed(title=":white_check_mark:ウイルスは検出されませんでした。[Virus Undetected]", description="※この結果は参考にするのみにしてください。0266st並びにVirustotalはこの結果を保証しません。", color=0x0000FF)
            return embed, False
        else:
            embed = discord.Embed(title=":warning:ウイルスが検出されました。[Virus Detected]", description="※この結果は参考にするのみにしてください。0266st並びにVirustotalはこの結果を保証しません。", color=0xFF0000)
        for d in dic["scans"]:
            if dic["scans"][d]["detected"] == True:
                #print("detected by " + d + " result : " + dic["scans"][d]["result"])
                embed.add_field(name=d, value="Type : " + dic["scans"][d]["result"])
        return embed, True
    elif type == "fileResult":
        if dic["attributes"]["stats"]["malicious"] >= 0:
            embed = discord.Embed(title=":warning:ウイルスが検出されました。[Virus Detected]", description="※この結果は参考にするのみにしてください。0266st並びにVirustotalはこの結果を保証しません。", color=0xFF0000)
        else:
            embed = discord.Embed(title=":white_check_mark:ウイルスは検出されませんでした。[Virus Undetected]", description="※この結果は参考にするのみにしてください。0266st並びにVirustotalはこの結果を保証しません。", color=0x0000FF)
            return embed, False
        for d in dic["attributes"]["results"]:
            if dic["attributes"]["results"][d]["category"] == "malicious":
                embed.add_field(name=d, value="Type : " + dic["attributes"]["results"][d]["result"])
        return embed, True
    return None


async def CheckFile(name: str) -> dict:
    global check_count
    if check_count <= 0:
        return None
    check_count -= 1
    global taskqueue
    taskqueue.put(name)
    res = None
    print("waiting for end file check...")
    with open("./download_files/" + name, "br") as e:
        res = await vt_client.scan_file_async(e, wait_for_completion=True)
    print("check end")
    return res.to_dict()

async def CheckHash(h: str) -> dict:
    global check_count
    if check_count <= 0:
        print("return None")
        return None
    check_count -= 1
    params = {'apikey': VT_API_KEY, 'resource': h}
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    async with aiohttp.ClientSession() as session:
        async with session.get(url=url, params=params) as res:
            res = await res.json()
            
    try:
        if res["response_code"] == 0:
            res["isEnable"] = False
        else:
            res["isEnable"] = True
    except:
        print("except")
        res["isEnable"] = True
    try:
        print(res["positives"])
    except:
        res["positives"] = 0
    return res
        
@cmdtree.command(name="setting", description="設定を変更します。※valueが指定されていない場合はコマンド、サブコマンドにかかわらず常にdisplayコマンドと同じ動作になります。")
@app_commands.describe(
    command="設定するコマンドです。",
    subcommand="サブコマンドです。コマンドにある場合は使用され、無ければ無視されます。",
    value="設定する値です。displayコマンドでは使用されません。この部分を指定しない場合はdisplayコマンドと同じ動作になります。"
)
async def setting(interaction: discord.Interaction, command: Literal["add", "delete", "display"], subcommand: Literal["AutoScan_channel", ""] = "", value = ""):
    global setting
    
    

async def main_loop():
    global check_count
    global checkcount_hour
    cnt = 0
    print("main loop started")
    while(True):
        check_count = 4
        if cnt % 60 == 0:
            checkcount_hour = 20
        cnt += 1
        await asyncio.sleep(60)
    return

def write_setting():
    global setting
    with open("./setting.json", "w") as f:
        json.dump(setting, f)
    return

def load_setting():
    with open("./setting/json", "r") as f:
        return json.load(f)

discord_client.run(DISCORD_API_TOKEN)