.class public final Llyiahf/vczjk/pp1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/pp1;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/pp1;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/pp1;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/pp1;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/pp1;->OooOOo0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    iget p2, p0, Llyiahf/vczjk/pp1;->OooOOO0:I

    packed-switch p2, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/j24;

    instance-of p2, p1, Llyiahf/vczjk/q37;

    iget-object v0, p0, Llyiahf/vczjk/pp1;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fl7;

    iget-object v1, p0, Llyiahf/vczjk/pp1;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/fl7;

    iget-object v2, p0, Llyiahf/vczjk/pp1;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/fl7;

    const/4 v3, 0x1

    if-eqz p2, :cond_0

    iget p1, v2, Llyiahf/vczjk/fl7;->element:I

    add-int/2addr p1, v3

    iput p1, v2, Llyiahf/vczjk/fl7;->element:I

    goto :goto_0

    :cond_0
    instance-of p2, p1, Llyiahf/vczjk/r37;

    if-eqz p2, :cond_1

    iget p1, v2, Llyiahf/vczjk/fl7;->element:I

    add-int/lit8 p1, p1, -0x1

    iput p1, v2, Llyiahf/vczjk/fl7;->element:I

    goto :goto_0

    :cond_1
    instance-of p2, p1, Llyiahf/vczjk/p37;

    if-eqz p2, :cond_2

    iget p1, v2, Llyiahf/vczjk/fl7;->element:I

    add-int/lit8 p1, p1, -0x1

    iput p1, v2, Llyiahf/vczjk/fl7;->element:I

    goto :goto_0

    :cond_2
    instance-of p2, p1, Llyiahf/vczjk/wo3;

    if-eqz p2, :cond_3

    iget p1, v1, Llyiahf/vczjk/fl7;->element:I

    add-int/2addr p1, v3

    iput p1, v1, Llyiahf/vczjk/fl7;->element:I

    goto :goto_0

    :cond_3
    instance-of p2, p1, Llyiahf/vczjk/xo3;

    if-eqz p2, :cond_4

    iget p1, v1, Llyiahf/vczjk/fl7;->element:I

    add-int/lit8 p1, p1, -0x1

    iput p1, v1, Llyiahf/vczjk/fl7;->element:I

    goto :goto_0

    :cond_4
    instance-of p2, p1, Llyiahf/vczjk/g83;

    if-eqz p2, :cond_5

    iget p1, v0, Llyiahf/vczjk/fl7;->element:I

    add-int/2addr p1, v3

    iput p1, v0, Llyiahf/vczjk/fl7;->element:I

    goto :goto_0

    :cond_5
    instance-of p1, p1, Llyiahf/vczjk/h83;

    if-eqz p1, :cond_6

    iget p1, v0, Llyiahf/vczjk/fl7;->element:I

    add-int/lit8 p1, p1, -0x1

    iput p1, v0, Llyiahf/vczjk/fl7;->element:I

    :cond_6
    :goto_0
    iget p1, v2, Llyiahf/vczjk/fl7;->element:I

    const/4 p2, 0x0

    if-lez p1, :cond_7

    move p1, v3

    goto :goto_1

    :cond_7
    move p1, p2

    :goto_1
    iget v1, v1, Llyiahf/vczjk/fl7;->element:I

    if-lez v1, :cond_8

    move v1, v3

    goto :goto_2

    :cond_8
    move v1, p2

    :goto_2
    iget v0, v0, Llyiahf/vczjk/fl7;->element:I

    if-lez v0, :cond_9

    move v0, v3

    goto :goto_3

    :cond_9
    move v0, p2

    :goto_3
    iget-object v2, p0, Llyiahf/vczjk/pp1;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/t12;

    iget-boolean v4, v2, Llyiahf/vczjk/t12;->OooOoo0:Z

    if-eq v4, p1, :cond_a

    iput-boolean p1, v2, Llyiahf/vczjk/t12;->OooOoo0:Z

    move p2, v3

    :cond_a
    iget-boolean p1, v2, Llyiahf/vczjk/t12;->OooOoo:Z

    if-eq p1, v1, :cond_b

    iput-boolean v1, v2, Llyiahf/vczjk/t12;->OooOoo:Z

    move p2, v3

    :cond_b
    iget-boolean p1, v2, Llyiahf/vczjk/t12;->OooOooO:Z

    if-eq p1, v0, :cond_c

    iput-boolean v0, v2, Llyiahf/vczjk/t12;->OooOooO:Z

    goto :goto_4

    :cond_c
    move v3, p2

    :goto_4
    if-eqz v3, :cond_d

    invoke-static {v2}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    :cond_d
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/pp1;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/lx4;

    if-eqz p1, :cond_e

    invoke-virtual {p2}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result p1

    if-eqz p1, :cond_e

    iget-object p1, p0, Llyiahf/vczjk/pp1;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/mk9;

    invoke-virtual {p1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v0

    iget-object p1, p1, Llyiahf/vczjk/mk9;->OooO0O0:Llyiahf/vczjk/s86;

    iget-object v1, p0, Llyiahf/vczjk/pp1;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/tl9;

    iget-object v2, p0, Llyiahf/vczjk/pp1;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/wv3;

    invoke-static {v1, p2, v0, v2, p1}, Llyiahf/vczjk/sb;->OooOOo(Llyiahf/vczjk/tl9;Llyiahf/vczjk/lx4;Llyiahf/vczjk/gl9;Llyiahf/vczjk/wv3;Llyiahf/vczjk/s86;)V

    goto :goto_5

    :cond_e
    invoke-static {p2}, Llyiahf/vczjk/sb;->OooOOOo(Llyiahf/vczjk/lx4;)V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
