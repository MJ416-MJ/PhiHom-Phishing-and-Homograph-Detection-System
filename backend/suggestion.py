def suggest_domain(best_match):
    if best_match is None or best_match=="":
        return ""
    else:
        return "Did you mean to visit "+ best_match +"?" 