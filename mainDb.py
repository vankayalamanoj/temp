import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Input = declarative_base()


class User(Input):

    '''
        This class is to create user table in the database
    '''
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Motors(Input):

    '''
        This class is used to create motors table in the database
    '''
    __tablename__ = 'Motors'

    id = Column(Integer, primary_key=True)
    uid = Column(Integer, ForeignKey('user.id'))
    item = Column(String(250), nullable=False)
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.item,
            'id': self.id,
        }


class Specifications(Input):
    '''
        this class is used to create specifications in the database
    '''
    __tablename__ = 'Specifications'

    id = Column(Integer, primary_key=True)
    pressure = Column(Integer, nullable=False)
    desc = Column(String(250), nullable=False)
    pumping = Column(Integer, nullable=False)
    price = Column(Integer, nullable=False)
    img = Column(String(250), nullable=False)
    motors_id = Column(Integer, ForeignKey('Motors.id'))
    products = relationship(Motors, cascade="all,delete")

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.desc,
            'id': self.id,
            'price': self.price,
            'pressure': self.pressure,
            'image': self.img,
            'pumping': self.pumping,
        }


engine = create_engine('sqlite:///motorItem.db')
Input.metadata.create_all(engine)
