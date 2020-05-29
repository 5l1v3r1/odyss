#!/usr/bin/env ruby
require "sinatra"
require "sinatra/json"
require "json"
require "open3"
require "digest"

set(:port, 8080)
set(:bind, "0.0.0.0")
set(:public_folder, "public")
main_html = File.open("/home/op/frontend/main.html", "r").read
start_html = File.open("/home/op/frontend/start.html", "r").read
key_path = "/home/op/.keys.json"
auth_path = "/home/op/.auth.json"
auth = {}
keys = []

if File.exist?(auth_path)
  auth = JSON.parse(File.open(auth_path).read)
else

  # I know this is bad, but it's just temporary. I think.
  File.open(auth_path, "w") { |f| f.write(JSON.generate({"master_key" => Digest::SHA256.hexdigest((Time.now.to_i * 5283).to_s)})) }
  auth = JSON.parse(File.open(auth_path).read)
end

if File.exist?(key_path)
  keys = JSON.parse(File.open(key_path).read)
else
  File.open(key_path, "w") { |f| f.write(JSON.generate([])) }
  keys = JSON.parse(File.open(key_path).read)
end

master_key = auth["master_key"]
requests = {}
global_machines = []

def key_exists(key, keys)
  key_exists = false

  keys.each do |data|
    if params[:key] == data["key"]
      key_exists = true
    end
  end

  return key_exists
end

get("/") do
  "It works!"
end

get("/start") do
  return start_html
end

get("/dashboard") do
  return main_html
end

get("/init/:key") do
  key = params[:key].gsub(/[^a-zA-Z0-9\-]/, "")

  if requests.has_key?(key)
    requests[key].push({"ip" => request.ip, "time" => Time.now.to_i})
  else
    requests[key] = [{"ip" => request.ip, "time" => Time.now.to_i}]
  end

  auth = false
  config = ""

  keys.each do |data|
    if key == data["key"]
      config = File.open("/home/op/profiles/#{data["uid"]}.ovpn").read
      auth = true
    end
  end

  if auth
    json(    "message" => "Key present!",     "auth" => true,     "config" => config)
  else
    json(    "message" => "Not authorized.",     "auth" => auth)
  end
end

get("/add/:key/:new_key") do
  headers(  "Access-Control-Allow-Origin" => "*")

  if params[:key] == master_key
    uid = Digest::SHA256.hexdigest(params[:new_key])
    pair = {"key" => params[:new_key], "uid" => uid}

    if !keys.include?(pair)
      stdout, stderr, status = Open3.capture3("sudo /home/op/openvpn/add-user.sh '#{uid}'")
      keys.push(pair)
      File.open(key_path, "w") { |f| f.write(JSON.generate(keys)) }
      json(      "message" => "Added successfully")
    else
      json(      "message" => "Key already exists")
    end
  end
end

get("/remove/:key/:new_key") do
  content_type(:json)
  headers(  "Access-Control-Allow-Origin" => "*",   "Access-Control-Allow-Methods" => ["OPTIONS", "GET", "POST"])

  if params[:key] == master_key

    keys.each do |data|
      key = data["key"]
      uid = data["uid"]

      if key == params[:new_key]
        pair = {"key" => key, "uid" => uid}
        keys.delete(pair)
        stdout, stderr, status = Open3.capture3("sudo /home/op/openvpn/revoke-user.sh '#{uid}'")
        File.open(key_path, "w") { |f| f.write(JSON.generate(keys)) }
        return JSON.generate({"message" => "Removed"})
      end
    end
  end
end

get("/heartbeats/all/:key") do
  headers(  "Access-Control-Allow-Origin" => "*")

  if params[:key] == master_key
    json(requests)
  end
end

get("/heartbeats/:key/:master_key") do
  headers(  "Access-Control-Allow-Origin" => "*")

  if params[:master_key] == master_key
    if requests.has_key?(params[:key])
      json(requests[params[:key]])
    end
  end
end

get("/heartbeats/:key") do
  headers(  "Access-Control-Allow-Origin" => "*")

  if params[:key] == master_key
    stdout, stderr, status = Open3.capture3("sudo grep \"10.8\" /etc/openvpn/openvpn-status.log")
    lines = stdout.split("\n")
    vpn_connects = []

    lines.each do |line|
      split = line.split(",")
      lan_ip = split[0]
      uid = split[1]
      external_ip = split[2]
      vpn_last_seen = split[3]
      vpn_connects.push({
        "Lan_IP" => lan_ip,
        "uid" => uid,
        "external_ip" => external_ip,
        "vpn_last_seen" => vpn_last_seen,
      })
    end

    machines = []
    appliances = requests.keys

    appliances.each do |appliance|
      connected = false
      last_heartbeat = requests[appliance].last

      vpn_connects.each do |vpn_connect|
        if vpn_connect["external_ip"].split(":")[0] == last_heartbeat["ip"] and (vpn_connect["uid"] == Digest::SHA256.hexdigest(appliance))
          connected = true
          two_minutes_ago_timestamp = Time.now.to_i - 20

          if two_minutes_ago_timestamp > last_heartbeat["time"]
            connected = false
          end

          added = false

          keys.each do |data|
            if data["key"] == appliance
              added = true
            end
          end

          machines.push({
            "key" => appliance,
            "uid" => vpn_connect["uid"],
            "lan_ip" => vpn_connect["Lan_IP"],
            "external_ip" => vpn_connect["external_ip"],
            "heartbeat_last_seen" => DateTime.strptime(last_heartbeat["time"].to_s, "%s").strftime("%c"),
            "vpn_last_seen" => vpn_connect["vpn_last_seen"],
            "connected" => connected,
            "authenticated" => added,
          })
          connected = true
        end
      end

      if !connected
        added = false

        keys.each do |data|
          if data["key"] == appliance
            added = true
          end
        end

        machines.push({
          "key" => appliance,
          "uid" => Digest::SHA256.hexdigest(appliance),
          "external_ip" => last_heartbeat["ip"],
          "heartbeat_last_seen" => DateTime.strptime(last_heartbeat["time"].to_s, "%s").strftime("%c"),
          "connected" => connected,
          "authenticated" => added,
        })
      end
    end

    global_machines = machines
    json(machines)
  end
end

get("/keys/:key") do
  headers(  "Access-Control-Allow-Origin" => "*")

  if params[:key] == master_key
    json(keys)
  end
end

get("/execute/:key/:master_key") do
  headers(  "Access-Control-Allow-Origin" => "*")

  if params[:master_key] == master_key
    if key_exists(params[:key], keys)
      top_machine = {}

      global_machines.each do |machine|
        if machine["key"] == params[:key]
          top_machine = machine
        end
      end

      if top_machine.has_key?("lan_ip")
        ip = top_machine["lan_ip"]
        stdout, stderr, status = Open3.capture3("ssh -o StrictHostKeyChecking=no root@#{ip} '#{params[:cmd]}'")
        json(        "response" => stdout)
      end

    else
      json(      "message" => "it dont exist tho")
    end
  end
end
