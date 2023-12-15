use crate::entities::prelude::Todo;
use crate::entities::todo;
use crate::guards::jwt_access::JwtAccessToken;
use rocket::{
    serde::{json::Json, Deserialize},
    State,
};
use sea_orm::{ActiveModelTrait, ActiveValue, DatabaseConnection, EntityTrait};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct CreateTodo<'r> {
    title: &'r str,
}

#[get("/")]
async fn get_todos(db: &State<DatabaseConnection>, _jwt: JwtAccessToken) -> Json<Vec<todo::Model>> {
    let db = db as &DatabaseConnection;

    let todos: Vec<todo::Model> = Todo::find().all(db).await.unwrap();

    Json(todos)
}

#[post("/", data = "<dto>")]
async fn create_todo(db: &State<DatabaseConnection>, dto: Json<CreateTodo<'_>>) -> Json<i32> {
    let db = db as &DatabaseConnection;

    let new_todo = todo::ActiveModel {
        title: ActiveValue::Set(dto.title.to_owned()),
        ..Default::default()
    };

    let id = Todo::insert(new_todo)
        .exec(db)
        .await
        .unwrap()
        .last_insert_id;

    Json(id)
}

#[put("/<id>")]
async fn checked_todo(db: &State<DatabaseConnection>, id: i32) {
    let db = db as &DatabaseConnection;

    let t = Todo::find_by_id(id).one(db).await.unwrap();

    let mut t: todo::ActiveModel = t.unwrap().into();

    t.done = ActiveValue::set(!t.done.unwrap());

    t.update(db).await.expect("cannot checked todo");
}

#[delete("/<id>")]
async fn delete_todo(db: &State<DatabaseConnection>, id: i32) {
    let db = db as &DatabaseConnection;

    Todo::delete_by_id(id).exec(db).await.unwrap();
}

pub fn routes() -> Vec<rocket::Route> {
    routes![get_todos, create_todo, checked_todo, delete_todo]
}
