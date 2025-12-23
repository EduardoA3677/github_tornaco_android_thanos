.class public final Llyiahf/vczjk/el9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $style:Llyiahf/vczjk/rn9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rn9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/el9;->$style:Llyiahf/vczjk/rn9;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p1, 0x5e56a525

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p1, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/f62;

    sget-object p3, Llyiahf/vczjk/ch1;->OooOO0O:Llyiahf/vczjk/l39;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/aa3;

    sget-object v0, Llyiahf/vczjk/ch1;->OooOOO:Llyiahf/vczjk/l39;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/yn4;

    iget-object v1, p0, Llyiahf/vczjk/el9;->$style:Llyiahf/vczjk/rn9;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    iget-object v2, p0, Llyiahf/vczjk/el9;->$style:Llyiahf/vczjk/rn9;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v1, :cond_0

    if-ne v3, v4, :cond_1

    :cond_0
    invoke-static {v2, v0}, Llyiahf/vczjk/er8;->OooOOoo(Llyiahf/vczjk/rn9;Llyiahf/vczjk/yn4;)Llyiahf/vczjk/rn9;

    move-result-object v3

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v3, Llyiahf/vczjk/rn9;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    const/4 v5, 0x0

    if-nez v1, :cond_2

    if-ne v2, v4, :cond_6

    :cond_2
    iget-object v1, v3, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-object v2, v1, Llyiahf/vczjk/dy8;->OooO0o:Llyiahf/vczjk/ba3;

    iget-object v6, v1, Llyiahf/vczjk/dy8;->OooO0OO:Llyiahf/vczjk/ib3;

    if-nez v6, :cond_3

    sget-object v6, Llyiahf/vczjk/ib3;->OooOOoo:Llyiahf/vczjk/ib3;

    :cond_3
    iget-object v7, v1, Llyiahf/vczjk/dy8;->OooO0Oo:Llyiahf/vczjk/cb3;

    if-eqz v7, :cond_4

    iget v7, v7, Llyiahf/vczjk/cb3;->OooO00o:I

    goto :goto_0

    :cond_4
    move v7, v5

    :goto_0
    iget-object v1, v1, Llyiahf/vczjk/dy8;->OooO0o0:Llyiahf/vczjk/db3;

    if-eqz v1, :cond_5

    iget v1, v1, Llyiahf/vczjk/db3;->OooO00o:I

    goto :goto_1

    :cond_5
    const v1, 0xffff

    :goto_1
    move-object v8, p3

    check-cast v8, Llyiahf/vczjk/ea3;

    invoke-virtual {v8, v2, v6, v7, v1}, Llyiahf/vczjk/ea3;->OooO0O0(Llyiahf/vczjk/ba3;Llyiahf/vczjk/ib3;II)Llyiahf/vczjk/i6a;

    move-result-object v2

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v2, Llyiahf/vczjk/p29;

    iget-object v1, p0, Llyiahf/vczjk/el9;->$style:Llyiahf/vczjk/rn9;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v4, :cond_7

    new-instance v6, Llyiahf/vczjk/bl9;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v7

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    iput-object v0, v6, Llyiahf/vczjk/bl9;->OooO00o:Llyiahf/vczjk/yn4;

    iput-object p1, v6, Llyiahf/vczjk/bl9;->OooO0O0:Llyiahf/vczjk/f62;

    iput-object p3, v6, Llyiahf/vczjk/bl9;->OooO0OO:Llyiahf/vczjk/aa3;

    iput-object v1, v6, Llyiahf/vczjk/bl9;->OooO0Oo:Llyiahf/vczjk/rn9;

    iput-object v7, v6, Llyiahf/vczjk/bl9;->OooO0o0:Ljava/lang/Object;

    invoke-static {v1, p1, p3}, Llyiahf/vczjk/oi9;->OooO0O0(Llyiahf/vczjk/rn9;Llyiahf/vczjk/f62;Llyiahf/vczjk/aa3;)J

    move-result-wide v7

    iput-wide v7, v6, Llyiahf/vczjk/bl9;->OooO0o:J

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v6, Llyiahf/vczjk/bl9;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    iget-object v2, v6, Llyiahf/vczjk/bl9;->OooO00o:Llyiahf/vczjk/yn4;

    if-ne v0, v2, :cond_8

    iget-object v2, v6, Llyiahf/vczjk/bl9;->OooO0O0:Llyiahf/vczjk/f62;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_8

    iget-object v2, v6, Llyiahf/vczjk/bl9;->OooO0OO:Llyiahf/vczjk/aa3;

    invoke-static {p3, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_8

    iget-object v2, v6, Llyiahf/vczjk/bl9;->OooO0Oo:Llyiahf/vczjk/rn9;

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_8

    iget-object v2, v6, Llyiahf/vczjk/bl9;->OooO0o0:Ljava/lang/Object;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_9

    :cond_8
    iput-object v0, v6, Llyiahf/vczjk/bl9;->OooO00o:Llyiahf/vczjk/yn4;

    iput-object p1, v6, Llyiahf/vczjk/bl9;->OooO0O0:Llyiahf/vczjk/f62;

    iput-object p3, v6, Llyiahf/vczjk/bl9;->OooO0OO:Llyiahf/vczjk/aa3;

    iput-object v3, v6, Llyiahf/vczjk/bl9;->OooO0Oo:Llyiahf/vczjk/rn9;

    iput-object v1, v6, Llyiahf/vczjk/bl9;->OooO0o0:Ljava/lang/Object;

    invoke-static {v3, p1, p3}, Llyiahf/vczjk/oi9;->OooO0O0(Llyiahf/vczjk/rn9;Llyiahf/vczjk/f62;Llyiahf/vczjk/aa3;)J

    move-result-wide v0

    iput-wide v0, v6, Llyiahf/vczjk/bl9;->OooO0o:J

    :cond_9
    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p3, :cond_a

    if-ne v0, v4, :cond_b

    :cond_a
    new-instance v0, Llyiahf/vczjk/dl9;

    invoke-direct {v0, v6}, Llyiahf/vczjk/dl9;-><init>(Llyiahf/vczjk/bl9;)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v0, Llyiahf/vczjk/bf3;

    invoke-static {p1, v0}, Landroidx/compose/ui/layout/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    invoke-virtual {p2, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
