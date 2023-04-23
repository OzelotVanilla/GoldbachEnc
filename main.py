from simulation_entities import User

if __name__ == "__main__":
    # Here we create two users to send message
    user_aurora = User("Featherine Augustus Aurora")
    user_beatrice = User("Beatrice Castiglioni")

    # User Aurora send Beatrice her public key
    user_aurora.sendPublicKeyTo(user_beatrice)

    # Now Beatrice can send message to Aurora
    message_in_the_network = user_beatrice.sendEncMsgTo(user_aurora.name, "Gold Witch Beatrice and Battler.")

    # The message itself looks like
    print(message_in_the_network)

    # And Aurora can decrypt it by her private key
    result = user_aurora.decryptEncMsg(message_in_the_network)
    print(f"User \"{user_aurora.name}\" got message:\n{result}")
