#! /usr/bin/python
# -*-coding:utf-8 -*-
# @Time     :   2020-12-21 18:35
# @Author   :   layven
from flask_sqlalchemy import SQLAlchemy
db=SQLAlchemy()

def init_ext(app):
    db.init_app(app)

from sqlalchemy.orm import class_mapper
from datetime import datetime
def serialize(model):
    models=[]
    try:
        if isinstance(model,list):
            for demo in model:
                columns=[c.key for c in class_mapper(demo.__class__).columns]
                demo_dic=dict((c,getattr(demo,c))for c in columns)
                for key,val in demo_dic.items():
                    if isinstance(val,datetime):
                        demo_dic[key]=str(val)
                models.append(demo_dic)
        else:
            columns=[c.keys for c in class_mapper(model.__class__).columns]
            demo_dic=dict((c,getattr(model,c))for c in columns)
            for key,val in demo_dic.items():
                if isinstance(val,datetime):
                    demo_dic[key]=str(val)
            models.append(demo_dic)
        return models
    except Exception as e:
        print(e)

class Test(db.Model):
    __tablename__="test"
    __table_args__={"useexisting":True}
    id=db.Column(db.Integer,autoincrement=True,primary_key=True)
    name=db.Column(db.String(45),default='')
    action=db.Column(db.String(45),default='')

