.class public abstract Llyiahf/vczjk/cu7;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ug1;
.implements Llyiahf/vczjk/fg2;
.implements Llyiahf/vczjk/vn4;


# instance fields
.field public final OooOoOO:Llyiahf/vczjk/n24;

.field public final OooOoo:F

.field public final OooOoo0:Z

.field public final OooOooO:Llyiahf/vczjk/w21;

.field public final OooOooo:Llyiahf/vczjk/le3;

.field public Oooo0:Z

.field public Oooo000:Llyiahf/vczjk/w29;

.field public Oooo00O:F

.field public Oooo00o:J

.field public final Oooo0O0:Llyiahf/vczjk/as5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n24;ZFLlyiahf/vczjk/w21;Llyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cu7;->OooOoOO:Llyiahf/vczjk/n24;

    iput-boolean p2, p0, Llyiahf/vczjk/cu7;->OooOoo0:Z

    iput p3, p0, Llyiahf/vczjk/cu7;->OooOoo:F

    iput-object p4, p0, Llyiahf/vczjk/cu7;->OooOooO:Llyiahf/vczjk/w21;

    iput-object p5, p0, Llyiahf/vczjk/cu7;->OooOooo:Llyiahf/vczjk/le3;

    const-wide/16 p1, 0x0

    iput-wide p1, p0, Llyiahf/vczjk/cu7;->Oooo00o:J

    new-instance p1, Llyiahf/vczjk/as5;

    invoke-direct {p1}, Llyiahf/vczjk/as5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cu7;->Oooo0O0:Llyiahf/vczjk/as5;

    return-void
.end method


# virtual methods
.method public final OooOOO0(J)V
    .locals 4

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/cu7;->Oooo0:Z

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    invoke-static {p1, p2}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide p1

    iput-wide p1, p0, Llyiahf/vczjk/cu7;->Oooo00o:J

    iget p1, p0, Llyiahf/vczjk/cu7;->OooOoo:F

    invoke-static {p1}, Ljava/lang/Float;->isNaN(F)Z

    move-result p2

    if-eqz p2, :cond_0

    iget-wide p1, p0, Llyiahf/vczjk/cu7;->Oooo00o:J

    sget v2, Llyiahf/vczjk/tt7;->OooO00o:F

    invoke-static {p1, p2}, Llyiahf/vczjk/tq8;->OooO0Oo(J)F

    move-result v2

    invoke-static {p1, p2}, Llyiahf/vczjk/tq8;->OooO0O0(J)F

    move-result p1

    invoke-static {v2, p1}, Llyiahf/vczjk/sb;->OooOO0o(FF)J

    move-result-wide p1

    invoke-static {p1, p2}, Llyiahf/vczjk/p86;->OooO0OO(J)F

    move-result p1

    const/high16 p2, 0x40000000    # 2.0f

    div-float/2addr p1, p2

    iget-boolean p2, p0, Llyiahf/vczjk/cu7;->OooOoo0:Z

    if-eqz p2, :cond_1

    sget p2, Llyiahf/vczjk/tt7;->OooO00o:F

    invoke-interface {v1, p2}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p2

    add-float/2addr p1, p2

    goto :goto_0

    :cond_0
    invoke-interface {v1, p1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p1

    :cond_1
    :goto_0
    iput p1, p0, Llyiahf/vczjk/cu7;->Oooo00O:F

    iget-object p1, p0, Llyiahf/vczjk/cu7;->Oooo0O0:Llyiahf/vczjk/as5;

    iget-object p2, p1, Llyiahf/vczjk/c76;->OooO00o:[Ljava/lang/Object;

    iget v1, p1, Llyiahf/vczjk/c76;->OooO0O0:I

    const/4 v2, 0x0

    :goto_1
    if-ge v2, v1, :cond_2

    aget-object v3, p2, v2

    check-cast v3, Llyiahf/vczjk/s37;

    invoke-virtual {p0, v3}, Llyiahf/vczjk/cu7;->o00000OO(Llyiahf/vczjk/s37;)V

    add-int/2addr v2, v0

    goto :goto_1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/as5;->OooO()V

    return-void
.end method

.method public final OooOo0o(Llyiahf/vczjk/to4;)V
    .locals 17

    move-object/from16 v1, p0

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-object v0, v1, Llyiahf/vczjk/cu7;->Oooo000:Llyiahf/vczjk/w29;

    move-object/from16 v2, p1

    iget-object v10, v2, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    if-eqz v0, :cond_1

    iget v5, v1, Llyiahf/vczjk/cu7;->Oooo00O:F

    iget-object v3, v1, Llyiahf/vczjk/cu7;->OooOooO:Llyiahf/vczjk/w21;

    invoke-interface {v3}, Llyiahf/vczjk/w21;->OooO00o()J

    move-result-wide v3

    iget-object v6, v0, Llyiahf/vczjk/w29;->OooO0OO:Llyiahf/vczjk/gi;

    invoke-virtual {v6}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    move-result v6

    const/4 v7, 0x0

    cmpl-float v7, v6, v7

    if-lez v7, :cond_1

    invoke-static {v6, v3, v4}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v3

    iget-boolean v0, v0, Llyiahf/vczjk/w29;->OooO00o:Z

    if-eqz v0, :cond_0

    invoke-interface {v10}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v6

    invoke-static {v6, v7}, Llyiahf/vczjk/tq8;->OooO0Oo(J)F

    move-result v14

    invoke-interface {v10}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v6

    invoke-static {v6, v7}, Llyiahf/vczjk/tq8;->OooO0O0(J)F

    move-result v15

    iget-object v6, v10, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {v6}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v7

    invoke-virtual {v6}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v0, v6, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vz5;

    iget-object v0, v0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uqa;

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v11

    const/4 v13, 0x0

    const/16 v16, 0x1

    const/4 v12, 0x0

    invoke-interface/range {v11 .. v16}, Llyiahf/vczjk/eq0;->OooOOOO(FFFFI)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    const/16 v9, 0x7c

    move-wide v11, v7

    move-object v8, v6

    const-wide/16 v6, 0x0

    move-object v13, v8

    const/4 v8, 0x0

    :try_start_1
    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/hg2;->OoooO0(Llyiahf/vczjk/hg2;JFJLlyiahf/vczjk/h79;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-static {v13, v11, v12}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    goto :goto_1

    :catchall_0
    move-exception v0

    goto :goto_0

    :catchall_1
    move-exception v0

    move-object v13, v6

    move-wide v11, v7

    :goto_0
    invoke-static {v13, v11, v12}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw v0

    :cond_0
    const/4 v8, 0x0

    const/16 v9, 0x7c

    const-wide/16 v6, 0x0

    move-object/from16 v2, p1

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/hg2;->OoooO0(Llyiahf/vczjk/hg2;JFJLlyiahf/vczjk/h79;I)V

    :cond_1
    :goto_1
    move-object v0, v1

    check-cast v0, Llyiahf/vczjk/tf;

    iget-object v2, v10, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {v2}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/tf;->Oooo0o0:Llyiahf/vczjk/xt7;

    if-eqz v3, :cond_2

    iget-wide v4, v0, Llyiahf/vczjk/cu7;->Oooo00o:J

    iget v6, v0, Llyiahf/vczjk/cu7;->Oooo00O:F

    invoke-static {v6}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v6

    iget-object v7, v0, Llyiahf/vczjk/cu7;->OooOooO:Llyiahf/vczjk/w21;

    invoke-interface {v7}, Llyiahf/vczjk/w21;->OooO00o()J

    move-result-wide v7

    iget-object v0, v0, Llyiahf/vczjk/cu7;->OooOooo:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/st7;

    iget v9, v0, Llyiahf/vczjk/st7;->OooO0Oo:F

    invoke-virtual/range {v3 .. v9}, Llyiahf/vczjk/xt7;->OooO0o0(JIJF)V

    invoke-static {v2}, Llyiahf/vczjk/t9;->OooO00o(Llyiahf/vczjk/eq0;)Landroid/graphics/Canvas;

    move-result-object v0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/xt7;->draw(Landroid/graphics/Canvas;)V

    :cond_2
    return-void
.end method

.method public final o00000OO(Llyiahf/vczjk/s37;)V
    .locals 12

    instance-of v0, p1, Llyiahf/vczjk/q37;

    if-eqz v0, :cond_c

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/q37;

    iget-wide v4, p0, Llyiahf/vczjk/cu7;->Oooo00o:J

    iget p1, p0, Llyiahf/vczjk/cu7;->Oooo00O:F

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/tf;

    iget-object v1, v0, Llyiahf/vczjk/tf;->Oooo0OO:Llyiahf/vczjk/wt7;

    const/4 v3, 0x0

    if-eqz v1, :cond_0

    goto :goto_3

    :cond_0
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0o:Llyiahf/vczjk/l39;

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/View;

    :goto_0
    instance-of v6, v1, Landroid/view/ViewGroup;

    if-nez v6, :cond_2

    move-object v6, v1

    check-cast v6, Landroid/view/View;

    invoke-virtual {v6}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v6

    instance-of v7, v6, Landroid/view/View;

    if-eqz v7, :cond_1

    move-object v1, v6

    goto :goto_0

    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Couldn\'t find a valid parent for "

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ". Are you overriding LocalView and providing a View that is not attached to the view hierarchy?"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    check-cast v1, Landroid/view/ViewGroup;

    invoke-virtual {v1}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v6

    move v7, v3

    :goto_1
    if-ge v7, v6, :cond_4

    invoke-virtual {v1, v7}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v8

    instance-of v9, v8, Llyiahf/vczjk/wt7;

    if-eqz v9, :cond_3

    check-cast v8, Llyiahf/vczjk/wt7;

    move-object v1, v8

    goto :goto_2

    :cond_3
    add-int/lit8 v7, v7, 0x1

    goto :goto_1

    :cond_4
    new-instance v6, Llyiahf/vczjk/wt7;

    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v7

    invoke-direct {v6, v7}, Llyiahf/vczjk/wt7;-><init>(Landroid/content/Context;)V

    invoke-virtual {v1, v6}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    move-object v1, v6

    :goto_2
    iput-object v1, v0, Llyiahf/vczjk/tf;->Oooo0OO:Llyiahf/vczjk/wt7;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :goto_3
    iget-object v6, v1, Llyiahf/vczjk/wt7;->OooOOOo:Llyiahf/vczjk/era;

    iget-object v7, v6, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v7, Ljava/util/LinkedHashMap;

    invoke-virtual {v7, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/xt7;

    if-eqz v7, :cond_5

    :goto_4
    move-object v1, v7

    goto/16 :goto_8

    :cond_5
    iget-object v7, v1, Llyiahf/vczjk/wt7;->OooOOOO:Ljava/util/ArrayList;

    const-string v8, "<this>"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v8

    const/4 v9, 0x0

    if-eqz v8, :cond_6

    move-object v7, v9

    goto :goto_5

    :cond_6
    invoke-virtual {v7, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    move-result-object v7

    :goto_5
    check-cast v7, Llyiahf/vczjk/xt7;

    iget-object v8, v6, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v8, Ljava/util/LinkedHashMap;

    iget-object v6, v6, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v6, Ljava/util/LinkedHashMap;

    if-nez v7, :cond_b

    iget v7, v1, Llyiahf/vczjk/wt7;->OooOOo0:I

    iget-object v10, v1, Llyiahf/vczjk/wt7;->OooOOO:Ljava/util/ArrayList;

    invoke-static {v10}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v11

    if-le v7, v11, :cond_7

    new-instance v7, Llyiahf/vczjk/xt7;

    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v9

    invoke-direct {v7, v9}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    invoke-virtual {v1, v7}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    invoke-virtual {v10, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_7
    iget v7, v1, Llyiahf/vczjk/wt7;->OooOOo0:I

    invoke-virtual {v10, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/xt7;

    invoke-virtual {v8, v7}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/tf;

    if-eqz v10, :cond_9

    iput-object v9, v10, Llyiahf/vczjk/tf;->Oooo0o0:Llyiahf/vczjk/xt7;

    invoke-static {v10}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    invoke-virtual {v6, v10}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/xt7;

    if-eqz v9, :cond_8

    invoke-interface {v8, v9}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/tf;

    :cond_8
    invoke-interface {v6, v10}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v7}, Llyiahf/vczjk/xt7;->OooO0OO()V

    :cond_9
    :goto_6
    iget v9, v1, Llyiahf/vczjk/wt7;->OooOOo0:I

    iget v10, v1, Llyiahf/vczjk/wt7;->OooOOO0:I

    add-int/lit8 v10, v10, -0x1

    if-ge v9, v10, :cond_a

    add-int/lit8 v9, v9, 0x1

    iput v9, v1, Llyiahf/vczjk/wt7;->OooOOo0:I

    goto :goto_7

    :cond_a
    iput v3, v1, Llyiahf/vczjk/wt7;->OooOOo0:I

    :cond_b
    :goto_7
    invoke-interface {v6, v0, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-interface {v8, v7, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_4

    :goto_8
    invoke-static {p1}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v6

    iget-object p1, v0, Llyiahf/vczjk/cu7;->OooOooO:Llyiahf/vczjk/w21;

    invoke-interface {p1}, Llyiahf/vczjk/w21;->OooO00o()J

    move-result-wide v7

    iget-object p1, v0, Llyiahf/vczjk/cu7;->OooOooo:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/st7;

    iget v9, p1, Llyiahf/vczjk/st7;->OooO0Oo:F

    new-instance v10, Llyiahf/vczjk/sf;

    invoke-direct {v10, v0}, Llyiahf/vczjk/sf;-><init>(Llyiahf/vczjk/tf;)V

    iget-boolean v3, v0, Llyiahf/vczjk/cu7;->OooOoo0:Z

    invoke-virtual/range {v1 .. v10}, Llyiahf/vczjk/xt7;->OooO0O0(Llyiahf/vczjk/q37;ZJIJFLlyiahf/vczjk/sf;)V

    iput-object v1, v0, Llyiahf/vczjk/tf;->Oooo0o0:Llyiahf/vczjk/xt7;

    invoke-static {v0}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    return-void

    :cond_c
    instance-of v0, p1, Llyiahf/vczjk/r37;

    if-eqz v0, :cond_d

    check-cast p1, Llyiahf/vczjk/r37;

    iget-object p1, p1, Llyiahf/vczjk/r37;->OooO00o:Llyiahf/vczjk/q37;

    move-object p1, p0

    check-cast p1, Llyiahf/vczjk/tf;

    iget-object p1, p1, Llyiahf/vczjk/tf;->Oooo0o0:Llyiahf/vczjk/xt7;

    if-eqz p1, :cond_e

    invoke-virtual {p1}, Llyiahf/vczjk/xt7;->OooO0Oo()V

    return-void

    :cond_d
    instance-of v0, p1, Llyiahf/vczjk/p37;

    if-eqz v0, :cond_e

    check-cast p1, Llyiahf/vczjk/p37;

    iget-object p1, p1, Llyiahf/vczjk/p37;->OooO00o:Llyiahf/vczjk/q37;

    move-object p1, p0

    check-cast p1, Llyiahf/vczjk/tf;

    iget-object p1, p1, Llyiahf/vczjk/tf;->Oooo0o0:Llyiahf/vczjk/xt7;

    if-eqz p1, :cond_e

    invoke-virtual {p1}, Llyiahf/vczjk/xt7;->OooO0Oo()V

    :cond_e
    return-void
.end method

.method public final o0O0O00()V
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/bu7;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/bu7;-><init>(Llyiahf/vczjk/cu7;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
