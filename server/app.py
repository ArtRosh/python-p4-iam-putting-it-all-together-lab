#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()

        try:
            new_user = User(
                username=data.get("username"),
                image_url=data.get("image_url"),
                bio=data.get("bio"),
            )
            new_user.password_hash = data.get("password")

            db.session.add(new_user)
            db.session.commit()

        except IntegrityError:
            return {"errors": ["Username already exists"]}, 422

        except ValueError as e:
            return {"errors": [str(e)]}, 422

        session["user_id"] = new_user.id
        return new_user.to_dict(), 201
        

class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        if not user:
            return {"error": "Unauthorized"}, 401

        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        
        # retrieve username and password from front
        username = data.get("username")
        password = data.get("password")

        # looking the user in database
        user = User.query.filter_by(username=username).first()

        if not user or not user.authenticate(password):
            return {"error": "Unauthorized"}, 401
        
        # if login success: save in session
        session["user_id"] = user.id

        # return user and status to front
        return user.to_dict(), 200


class Logout(Resource):
    def delete(self):
        # check if user logged in 
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401
        
        # remove user_id from session
        session.pop("user_id", None)

        # return empty response with 204
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        # 1. Check if user logged in
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401
        
        # 2. Query all recipes belongs to the user
        recipes = Recipe.query.filter_by(user_id=user_id).all()

        # 3. Return list of recipes to_dict()
        return [recipes.to_dict() for recipes in recipes], 200
    
    def post(self):
        # 1. Chect if user logged in 
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401
        
        data = request.get_json()

        try:
            # 2. Create ricipe belongs to the user
            new_recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )

            db.session.add(new_recipe)
            db.session.commit()

        # 3. Catch errors validation of model
        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422
        
        # 4. If everything ok, return created recipe
        return new_recipe.to_dict(), 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)