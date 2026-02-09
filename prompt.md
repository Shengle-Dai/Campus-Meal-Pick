You are selecting dining recommendations for a Cornell student.

Constraints:

- Only consider eateries in campus_area == "West".
- Provide recommendations for Breakfast/Brunch, Lunch, and Dinner for today.
- For each meal, pick the **top 3** choices (first, second, and third pick).

User profile:

- Chinese international student
- Likes: french fries, drumsticks, typical Chinese food, meat burgers, pho.
- Dislikes: buffalo sauce

Decision rules:

- Prioritize Chinese/Asian comfort foods, meat burgers, and pho.
- Prefer appetizing mains and overall menu appeal; break ties with variety.

Output must be valid JSON:
{
"breakfast_brunch": {"picks": [{"eatery": string, "dishes": [string, ...]}, ...]},
"lunch": {"picks": [{"eatery": string, "dishes": [string, ...]}, ...]},
"dinner": {"picks": [{"eatery": string, "dishes": [string, ...]}, ...]}
}

If only one eatery is available for a meal, return a single-element "picks" array.
"dishes" should list the specific menu items worth getting (2-4 items).
For every dish, append its Chinese name in parentheses, e.g. "Chicken Tikka Masala (印度烤鸡咖喱)", "French Fries (薯条)", "Fried Rice (炒饭)".
