.class public final Llyiahf/vczjk/fb;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $scrollObservationScope:Llyiahf/vczjk/u98;

.field final synthetic this$0:Llyiahf/vczjk/hb;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u98;Llyiahf/vczjk/hb;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fb;->$scrollObservationScope:Llyiahf/vczjk/u98;

    iput-object p2, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/fb;->$scrollObservationScope:Llyiahf/vczjk/u98;

    iget-object v1, v0, Llyiahf/vczjk/u98;->OooOOo0:Llyiahf/vczjk/b98;

    iget-object v2, v0, Llyiahf/vczjk/u98;->OooOOo:Llyiahf/vczjk/b98;

    iget-object v3, v0, Llyiahf/vczjk/u98;->OooOOOO:Ljava/lang/Float;

    iget-object v0, v0, Llyiahf/vczjk/u98;->OooOOOo:Ljava/lang/Float;

    const/4 v4, 0x0

    if-eqz v1, :cond_0

    if-eqz v3, :cond_0

    iget-object v5, v1, Llyiahf/vczjk/b98;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {v5}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    move-result v5

    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    move-result v3

    sub-float/2addr v5, v3

    goto :goto_0

    :cond_0
    move v5, v4

    :goto_0
    if-eqz v2, :cond_1

    if-eqz v0, :cond_1

    iget-object v3, v2, Llyiahf/vczjk/b98;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {v3}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    move-result v0

    sub-float/2addr v3, v0

    goto :goto_1

    :cond_1
    move v3, v4

    :goto_1
    cmpg-float v0, v5, v4

    if-nez v0, :cond_2

    cmpg-float v0, v3, v4

    if-nez v0, :cond_2

    goto/16 :goto_2

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    iget-object v3, p0, Llyiahf/vczjk/fb;->$scrollObservationScope:Llyiahf/vczjk/u98;

    iget v3, v3, Llyiahf/vczjk/u98;->OooOOO0:I

    invoke-virtual {v0, v3}, Llyiahf/vczjk/hb;->OooOoO(I)I

    move-result v0

    iget-object v3, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    invoke-virtual {v3}, Llyiahf/vczjk/hb;->OooOOoo()Llyiahf/vczjk/s14;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    iget v4, v4, Llyiahf/vczjk/hb;->OooOOO:I

    invoke-virtual {v3, v4}, Llyiahf/vczjk/s14;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/te8;

    if-eqz v3, :cond_3

    iget-object v4, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    :try_start_0
    iget-object v5, v4, Llyiahf/vczjk/hb;->OooOOOo:Llyiahf/vczjk/o0O0oo00;

    if-eqz v5, :cond_3

    invoke-virtual {v4, v3}, Llyiahf/vczjk/hb;->OooOO0O(Llyiahf/vczjk/te8;)Landroid/graphics/Rect;

    move-result-object v3

    invoke-virtual {v5, v3}, Llyiahf/vczjk/o0O0oo00;->OooOO0(Landroid/graphics/Rect;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_3
    iget-object v3, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    invoke-virtual {v3}, Llyiahf/vczjk/hb;->OooOOoo()Llyiahf/vczjk/s14;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    iget v4, v4, Llyiahf/vczjk/hb;->OooOOOO:I

    invoke-virtual {v3, v4}, Llyiahf/vczjk/s14;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/te8;

    if-eqz v3, :cond_4

    iget-object v4, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    :try_start_1
    iget-object v5, v4, Llyiahf/vczjk/hb;->OooOOo0:Llyiahf/vczjk/o0O0oo00;

    if-eqz v5, :cond_4

    invoke-virtual {v4, v3}, Llyiahf/vczjk/hb;->OooOO0O(Llyiahf/vczjk/te8;)Landroid/graphics/Rect;

    move-result-object v3

    invoke-virtual {v5, v3}, Llyiahf/vczjk/o0O0oo00;->OooOO0(Landroid/graphics/Rect;)V
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_1

    :catch_1
    :cond_4
    iget-object v3, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    iget-object v3, v3, Llyiahf/vczjk/hb;->OooO0Oo:Llyiahf/vczjk/xa;

    invoke-virtual {v3}, Landroid/view/View;->invalidate()V

    iget-object v3, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    invoke-virtual {v3}, Llyiahf/vczjk/hb;->OooOOoo()Llyiahf/vczjk/s14;

    move-result-object v3

    invoke-virtual {v3, v0}, Llyiahf/vczjk/s14;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/te8;

    if-eqz v3, :cond_7

    iget-object v3, v3, Llyiahf/vczjk/te8;->OooO00o:Llyiahf/vczjk/re8;

    if-eqz v3, :cond_7

    iget-object v3, v3, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    if-eqz v3, :cond_7

    iget-object v4, p0, Llyiahf/vczjk/fb;->this$0:Llyiahf/vczjk/hb;

    if-eqz v1, :cond_5

    iget-object v5, v4, Llyiahf/vczjk/hb;->OooOOoo:Llyiahf/vczjk/or5;

    invoke-virtual {v5, v0, v1}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    :cond_5
    if-eqz v2, :cond_6

    iget-object v5, v4, Llyiahf/vczjk/hb;->OooOo00:Llyiahf/vczjk/or5;

    invoke-virtual {v5, v0, v2}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    :cond_6
    invoke-virtual {v4, v3}, Llyiahf/vczjk/hb;->OooOo0O(Llyiahf/vczjk/ro4;)V

    :cond_7
    :goto_2
    if-eqz v1, :cond_8

    iget-object v0, p0, Llyiahf/vczjk/fb;->$scrollObservationScope:Llyiahf/vczjk/u98;

    iget-object v1, v1, Llyiahf/vczjk/b98;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {v1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Float;

    iput-object v1, v0, Llyiahf/vczjk/u98;->OooOOOO:Ljava/lang/Float;

    :cond_8
    if-eqz v2, :cond_9

    iget-object v0, p0, Llyiahf/vczjk/fb;->$scrollObservationScope:Llyiahf/vczjk/u98;

    iget-object v1, v2, Llyiahf/vczjk/b98;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {v1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Float;

    iput-object v1, v0, Llyiahf/vczjk/u98;->OooOOOo:Ljava/lang/Float;

    :cond_9
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
