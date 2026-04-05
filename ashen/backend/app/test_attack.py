from app.services.attack_recommender import recommend_attacks

result = recommend_attacks("Open port 21 FTP detected")

print(result)