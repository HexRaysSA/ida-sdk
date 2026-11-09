/****************************************************************************
**
** Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the examples of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial Usage
** Licensees holding valid Qt Commercial licenses may use this file in
** accordance with the Qt Commercial License Agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and Nokia.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU Lesser General Public License version 2.1 requirements
** will be met: http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** In addition, as a special exception, Nokia gives you certain additional
** rights.  These rights are described in the Nokia Qt LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3.0 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU General Public License version 3.0 requirements will be
** met: http://www.gnu.org/copyleft/gpl.html.
**
** If you have questions regarding the use of this file, please contact
** Nokia at qt-info@nokia.com.
** $QT_END_LICENSE$
**
****************************************************************************/

//lint -e4206 'nodiscard' attribute cannot be applied to types
#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:5219) // implicit conversion from 'int' to 'float', possible loss of data
#pragma warning(disable:5240) // 'nodiscard': attribute is ignored in this syntactic position
#endif // __NT__

#include <QGraphicsScene>
#include <QGraphicsSceneMouseEvent>
#include <QPainter>
#include <QStyleOption>

#include "edge.h"
#include "node.h"
#include "graphwidget.h"

#ifdef __NT__
#pragma warning(pop)
#endif // __NT__

//lint -e665 unparenthesized parameter
//lint -e666 expression with side effects passed to repeated parameter
//lint -e790 possibly truncated multiplication

const char html[] =
    "<span style=\"white-space: pre; font-family: FixedSys; color: blue; background: white\">"
    "<span style=\"color:navy\">push    </span><span style=\"color:green\">0</span>\n"
    "<span style=\"color:navy\">push    [ebp+</span><span style=\"color:green\">argv</span><span style=\"color:navy\">]</span>\n"
    "<span style=\"color:navy\">call    sub_4015B8</span>";

Node::Node(GraphWidget *graphWidget)
  : graph(graphWidget)
{
  setFlag(ItemIsMovable);
  setFlag(ItemIsFocusable);
  setFlag(ItemIsSelectable);
  setFlag(ItemSendsGeometryChanges);
  setCacheMode(DeviceCoordinateCache);
  setZValue(-1);
  setHtml(html);
}

void Node::addEdge(Edge *edge)
{
  edgeList << edge;
  edge->adjust();
}

QList<Edge *> Node::edges() const
{
  return edgeList;
}

void Node::calculateForces()
{
  if ( !scene() || scene()->mouseGrabberItem() == this )
  {
    newPos = pos();
    return;
  }

  // Sum up all forces pushing this item away
  qreal xvel = 0;
  qreal yvel = 0;
  foreach ( QGraphicsItem *item, scene()->items() )
  {
    Node *node = qgraphicsitem_cast<Node *>(item);
    if ( !node )
      continue;

    QLineF line(mapFromItem(node, 0, 0), QPointF(0, 0));
    qreal dx = line.dx();
    qreal dy = line.dy();
    double l = 2.0 * (dx * dx + dy * dy);
    if ( l > 0 )
    {
      xvel += (dx * 150.0) / l;
      yvel += (dy * 150.0) / l;
    }
  }

  // Now subtract all forces pulling items together
  double weight = (edgeList.size() + 1) * 100;
  foreach ( Edge *edge, edgeList )
  {
    QPointF _pos;
    if ( edge->sourceNode() == this )
      _pos = mapFromItem(edge->destNode(), 0, 0);
    else
      _pos = mapFromItem(edge->sourceNode(), 0, 0);
    xvel += _pos.x() / weight;
    yvel += _pos.y() / weight;
  }

  if ( qAbs(xvel) < 0.1 && qAbs(yvel) < 0.1 )
    xvel = yvel = 0;

  QRectF sceneRect = scene()->sceneRect();
  newPos = pos() + QPointF(xvel, yvel);
  newPos.setX(qMin(qMax(newPos.x(), sceneRect.left() + 10), sceneRect.right() - 10));
  newPos.setY(qMin(qMax(newPos.y(), sceneRect.top() + 10), sceneRect.bottom() - 10));
}

bool Node::_advance()
{
  if ( newPos == pos() )
    return false;

  setPos(newPos);
  return true;
}

QVariant Node::itemChange(GraphicsItemChange change, const QVariant &value)
{
  switch ( change )
  {
    case ItemPositionHasChanged:
      foreach ( Edge *edge, edgeList )
        edge->adjust();
      graph->itemMoved();
      break;
    default:
      break;
  }

  return QGraphicsTextItem::itemChange(change, value);
}

void Node::paint(QPainter *painter, const QStyleOptionGraphicsItem *option, QWidget *widget)
{
  painter->fillRect(option->rect, Qt::white);
  QGraphicsTextItem::paint(painter, option, widget);
}

void Node::mousePressEvent(QGraphicsSceneMouseEvent *_event)
{
  update();
  QGraphicsTextItem::mousePressEvent(_event);
}

void Node::mouseReleaseEvent(QGraphicsSceneMouseEvent *_event)
{
  update();
  QGraphicsTextItem::mouseReleaseEvent(_event);
}
