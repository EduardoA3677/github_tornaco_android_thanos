.class public Llyiahf/vczjk/d26;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ws5;

.field public final OooO0O0:Llyiahf/vczjk/as5;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/ws5;

    const/16 v1, 0x10

    new-array v1, v1, [Llyiahf/vczjk/j16;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    new-instance v0, Llyiahf/vczjk/as5;

    const/16 v1, 0xa

    invoke-direct {v0, v1}, Llyiahf/vczjk/as5;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/d26;->OooO0O0:Llyiahf/vczjk/as5;

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/i65;Llyiahf/vczjk/xn4;Llyiahf/vczjk/hl1;Z)Z
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    iget-object v1, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x0

    move v3, v2

    move v4, v3

    :goto_0
    if-ge v3, v0, :cond_2

    aget-object v5, v1, v3

    check-cast v5, Llyiahf/vczjk/j16;

    invoke-virtual {v5, p1, p2, p3, p4}, Llyiahf/vczjk/j16;->OooO00o(Llyiahf/vczjk/i65;Llyiahf/vczjk/xn4;Llyiahf/vczjk/hl1;Z)Z

    move-result v5

    if-nez v5, :cond_1

    if-eqz v4, :cond_0

    goto :goto_1

    :cond_0
    move v4, v2

    goto :goto_2

    :cond_1
    :goto_1
    const/4 v4, 0x1

    :goto_2
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_2
    return v4
.end method

.method public OooO0O0(Llyiahf/vczjk/hl1;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/d26;->OooO00o:Llyiahf/vczjk/ws5;

    iget v0, p1, Llyiahf/vczjk/ws5;->OooOOOO:I

    add-int/lit8 v0, v0, -0x1

    :goto_0
    const/4 v1, -0x1

    if-ge v1, v0, :cond_1

    iget-object v1, p1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v1, v1, v0

    check-cast v1, Llyiahf/vczjk/j16;

    iget-object v1, v1, Llyiahf/vczjk/j16;->OooO0Oo:Llyiahf/vczjk/w3;

    iget v1, v1, Llyiahf/vczjk/w3;->OooOOO0:I

    if-nez v1, :cond_0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    :cond_0
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    return-void
.end method
