.class public final Llyiahf/vczjk/ld6;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# static fields
.field public static final OooO0o:Llyiahf/vczjk/ld6;

.field public static final OooO0o0:Llyiahf/vczjk/ld6;

.field public static final OooO0oO:Llyiahf/vczjk/ld6;

.field public static final OooO0oo:Llyiahf/vczjk/ld6;


# instance fields
.field public final synthetic OooO0Oo:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/ld6;

    const/4 v1, 0x1

    const/4 v2, 0x2

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/ld6;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/ld6;->OooO0o0:Llyiahf/vczjk/ld6;

    new-instance v0, Llyiahf/vczjk/ld6;

    const/4 v1, 0x1

    const/4 v2, 0x1

    invoke-direct {v0, v1, v1, v2}, Llyiahf/vczjk/ld6;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/ld6;->OooO0o:Llyiahf/vczjk/ld6;

    new-instance v0, Llyiahf/vczjk/ld6;

    const/4 v1, 0x1

    const/4 v2, 0x2

    const/4 v3, 0x2

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/ld6;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/ld6;->OooO0oO:Llyiahf/vczjk/ld6;

    new-instance v0, Llyiahf/vczjk/ld6;

    const/4 v1, 0x1

    const/4 v2, 0x3

    invoke-direct {v0, v1, v1, v2}, Llyiahf/vczjk/ld6;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/ld6;->OooO0oo:Llyiahf/vczjk/ld6;

    return-void
.end method

.method public synthetic constructor <init>(III)V
    .locals 1

    iput p3, p0, Llyiahf/vczjk/ld6;->OooO0Oo:I

    const/4 p3, 0x2

    const/4 v0, 0x0

    invoke-direct {p0, p1, p2, p3, v0}, Llyiahf/vczjk/b23;-><init>(IIIB)V

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/j11;Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/ld6;->OooO0Oo:I

    packed-switch v0, :pswitch_data_0

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/j11;->OooO0o0(I)I

    move-result p1

    instance-of p2, v0, Llyiahf/vczjk/oo7;

    if-eqz p2, :cond_0

    move-object p2, v0

    check-cast p2, Llyiahf/vczjk/oo7;

    iget-object v1, p4, Llyiahf/vczjk/go7;->OooO0OO:Llyiahf/vczjk/ws5;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_0
    iget p2, p3, Llyiahf/vczjk/os8;->OooOo00:I

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/os8;->Oooo0o0(II)I

    move-result p2

    invoke-virtual {p3, p2}, Llyiahf/vczjk/os8;->OooO0oO(I)I

    move-result p2

    iget-object v1, p3, Llyiahf/vczjk/os8;->OooO0OO:[Ljava/lang/Object;

    aget-object v2, v1, p2

    aput-object v0, v1, p2

    instance-of p2, v2, Llyiahf/vczjk/oo7;

    if-eqz p2, :cond_1

    invoke-virtual {p3}, Llyiahf/vczjk/os8;->OooOOOO()I

    move-result p2

    iget v0, p3, Llyiahf/vczjk/os8;->OooOo00:I

    invoke-virtual {p3, v0, p1}, Llyiahf/vczjk/os8;->Oooo0o0(II)I

    move-result p1

    sub-int/2addr p2, p1

    check-cast v2, Llyiahf/vczjk/oo7;

    const/4 p1, -0x1

    invoke-virtual {p4, v2, p2, p1, p1}, Llyiahf/vczjk/go7;->OooO0Oo(Ljava/lang/Object;III)V

    goto :goto_0

    :cond_1
    instance-of p1, v2, Llyiahf/vczjk/aj7;

    if-eqz p1, :cond_2

    check-cast v2, Llyiahf/vczjk/aj7;

    invoke-virtual {v2}, Llyiahf/vczjk/aj7;->OooO0o0()V

    :cond_2
    :goto_0
    return-void

    :pswitch_0
    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/d7;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/j11;->OooO0o0(I)I

    move-result p1

    instance-of p2, v0, Llyiahf/vczjk/oo7;

    if-eqz p2, :cond_3

    move-object p2, v0

    check-cast p2, Llyiahf/vczjk/oo7;

    iget-object v2, p4, Llyiahf/vczjk/go7;->OooO0OO:Llyiahf/vczjk/ws5;

    invoke-virtual {v2, p2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_3
    invoke-virtual {p3, v1}, Llyiahf/vczjk/os8;->OooO0OO(Llyiahf/vczjk/d7;)I

    move-result p2

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/os8;->Oooo0o0(II)I

    move-result v1

    invoke-virtual {p3, v1}, Llyiahf/vczjk/os8;->OooO0oO(I)I

    move-result v1

    iget-object v2, p3, Llyiahf/vczjk/os8;->OooO0OO:[Ljava/lang/Object;

    aget-object v3, v2, v1

    aput-object v0, v2, v1

    instance-of v0, v3, Llyiahf/vczjk/oo7;

    if-eqz v0, :cond_5

    invoke-virtual {p3}, Llyiahf/vczjk/os8;->OooOOOO()I

    move-result v0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/os8;->Oooo0o0(II)I

    move-result p1

    sub-int/2addr v0, p1

    check-cast v3, Llyiahf/vczjk/oo7;

    iget-object p1, v3, Llyiahf/vczjk/oo7;->OooO0O0:Llyiahf/vczjk/d7;

    if-eqz p1, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/d7;->OooO00o()Z

    move-result p2

    if-eqz p2, :cond_4

    invoke-virtual {p3, p1}, Llyiahf/vczjk/os8;->OooO0OO(Llyiahf/vczjk/d7;)I

    move-result p1

    invoke-virtual {p3}, Llyiahf/vczjk/os8;->OooOOOO()I

    move-result p2

    invoke-virtual {p3, p1}, Llyiahf/vczjk/os8;->Oooo0o(I)I

    move-result p3

    sub-int/2addr p2, p3

    goto :goto_1

    :cond_4
    const/4 p1, -0x1

    move p2, p1

    :goto_1
    invoke-virtual {p4, v3, v0, p1, p2}, Llyiahf/vczjk/go7;->OooO0Oo(Ljava/lang/Object;III)V

    goto :goto_2

    :cond_5
    instance-of p1, v3, Llyiahf/vczjk/aj7;

    if-eqz p1, :cond_6

    check-cast v3, Llyiahf/vczjk/aj7;

    invoke-virtual {v3}, Llyiahf/vczjk/aj7;->OooO0o0()V

    :cond_6
    :goto_2
    return-void

    :pswitch_1
    const/4 p4, 0x0

    invoke-virtual {p1, p4}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/d7;

    invoke-virtual {p1, p4}, Llyiahf/vczjk/j11;->OooO0o0(I)I

    move-result p1

    invoke-interface {p2}, Llyiahf/vczjk/cx;->OooOOO0()V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/os8;->OooO0OO(Llyiahf/vczjk/d7;)I

    move-result p4

    invoke-virtual {p3, p4}, Llyiahf/vczjk/os8;->OooOoo0(I)Ljava/lang/Object;

    move-result-object p3

    invoke-interface {p2, p1, p3}, Llyiahf/vczjk/cx;->OooO0O0(ILjava/lang/Object;)V

    return-void

    :pswitch_2
    const/4 p4, 0x0

    invoke-virtual {p1, p4}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/d7;

    invoke-virtual {p1, p4}, Llyiahf/vczjk/j11;->OooO0o0(I)I

    move-result p1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/os8;->OooO0OO(Llyiahf/vczjk/d7;)I

    move-result p4

    invoke-virtual {p3, p4, v0}, Llyiahf/vczjk/os8;->OoooO0O(ILjava/lang/Object;)V

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/cx;->OooOOO(ILjava/lang/Object;)V

    invoke-interface {p2, v0}, Llyiahf/vczjk/cx;->OooO0OO(Ljava/lang/Object;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
