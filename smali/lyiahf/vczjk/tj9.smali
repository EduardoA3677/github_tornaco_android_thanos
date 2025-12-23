.class public final Llyiahf/vczjk/tj9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $enabled:Z

.field final synthetic $interactionSource:Llyiahf/vczjk/rr5;

.field final synthetic $scrollerPosition:Llyiahf/vczjk/vj9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vj9;ZLlyiahf/vczjk/rr5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iput-boolean p2, p0, Llyiahf/vczjk/tj9;->$enabled:Z

    iput-object p3, p0, Llyiahf/vczjk/tj9;->$interactionSource:Llyiahf/vczjk/rr5;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p1, 0x3001dc2a

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p1, Llyiahf/vczjk/ch1;->OooOOO:Llyiahf/vczjk/l39;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    sget-object p3, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    const/4 v0, 0x1

    const/4 v1, 0x0

    if-ne p1, p3, :cond_0

    move p1, v0

    goto :goto_0

    :cond_0
    move p1, v1

    :goto_0
    iget-object p3, p0, Llyiahf/vczjk/tj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iget-object p3, p3, Llyiahf/vczjk/vj9;->OooO0o:Llyiahf/vczjk/qs5;

    check-cast p3, Llyiahf/vczjk/fw8;

    invoke-virtual {p3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/nf6;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-eq p3, v2, :cond_2

    if-nez p1, :cond_1

    goto :goto_1

    :cond_1
    move p1, v1

    goto :goto_2

    :cond_2
    :goto_1
    move p1, v0

    :goto_2
    iget-object p3, p0, Llyiahf/vczjk/tj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    iget-object v2, p0, Llyiahf/vczjk/tj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p3, :cond_3

    if-ne v3, v4, :cond_4

    :cond_3
    new-instance v3, Llyiahf/vczjk/pj9;

    invoke-direct {v3, v2}, Llyiahf/vczjk/pj9;-><init>(Llyiahf/vczjk/vj9;)V

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-static {v3, p2}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object p3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v4, :cond_5

    new-instance v2, Llyiahf/vczjk/ta8;

    invoke-direct {v2, p3}, Llyiahf/vczjk/ta8;-><init>(Llyiahf/vczjk/qs5;)V

    new-instance p3, Llyiahf/vczjk/u32;

    invoke-direct {p3, v2}, Llyiahf/vczjk/u32;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v2, p3

    :cond_5
    check-cast v2, Llyiahf/vczjk/sa8;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    iget-object v3, p0, Llyiahf/vczjk/tj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr p3, v3

    iget-object v3, p0, Llyiahf/vczjk/tj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez p3, :cond_6

    if-ne v5, v4, :cond_7

    :cond_6
    new-instance v5, Llyiahf/vczjk/sj9;

    invoke-direct {v5, v2, v3}, Llyiahf/vczjk/sj9;-><init>(Llyiahf/vczjk/sa8;Llyiahf/vczjk/vj9;)V

    invoke-virtual {p2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v5, Llyiahf/vczjk/sj9;

    iget-object p3, p0, Llyiahf/vczjk/tj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iget-object p3, p3, Llyiahf/vczjk/vj9;->OooO0o:Llyiahf/vczjk/qs5;

    check-cast p3, Llyiahf/vczjk/fw8;

    invoke-virtual {p3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/nf6;

    iget-boolean v2, p0, Llyiahf/vczjk/tj9;->$enabled:Z

    if-eqz v2, :cond_8

    iget-object v2, p0, Llyiahf/vczjk/tj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iget-object v2, v2, Llyiahf/vczjk/vj9;->OooO0O0:Llyiahf/vczjk/lr5;

    check-cast v2, Llyiahf/vczjk/zv8;

    invoke-virtual {v2}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v2

    const/4 v3, 0x0

    cmpg-float v2, v2, v3

    if-nez v2, :cond_9

    :cond_8
    move v0, v1

    :cond_9
    iget-object v2, p0, Llyiahf/vczjk/tj9;->$interactionSource:Llyiahf/vczjk/rr5;

    invoke-static {v5, p3, v0, p1, v2}, Landroidx/compose/foundation/gestures/OooO0O0;->OooO0O0(Llyiahf/vczjk/sj9;Llyiahf/vczjk/nf6;ZZLlyiahf/vczjk/rr5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
