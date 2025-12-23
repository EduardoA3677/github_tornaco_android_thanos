.class public abstract Llyiahf/vczjk/yna;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ioa;

.field public OooO0O0:[Llyiahf/vczjk/x04;


# direct methods
.method public constructor <init>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ioa;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/ioa;-><init>(Llyiahf/vczjk/ioa;)V

    invoke-direct {p0, v0}, Llyiahf/vczjk/yna;-><init>(Llyiahf/vczjk/ioa;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yna;->OooO00o:Llyiahf/vczjk/ioa;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/yna;->OooO0O0:[Llyiahf/vczjk/x04;

    if-eqz v0, :cond_4

    const/4 v1, 0x0

    aget-object v1, v0, v1

    const/4 v2, 0x1

    aget-object v0, v0, v2

    iget-object v3, p0, Llyiahf/vczjk/yna;->OooO00o:Llyiahf/vczjk/ioa;

    if-nez v0, :cond_0

    iget-object v0, v3, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/4 v4, 0x2

    invoke-virtual {v0, v4}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v0

    :cond_0
    if-nez v1, :cond_1

    iget-object v1, v3, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v1

    :cond_1
    invoke-static {v1, v0}, Llyiahf/vczjk/x04;->OooO00o(Llyiahf/vczjk/x04;Llyiahf/vczjk/x04;)Llyiahf/vczjk/x04;

    move-result-object v0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yna;->OooO0oO(Llyiahf/vczjk/x04;)V

    iget-object v0, p0, Llyiahf/vczjk/yna;->OooO0O0:[Llyiahf/vczjk/x04;

    const/16 v1, 0x10

    invoke-static {v1}, Llyiahf/vczjk/ll6;->OooO0oo(I)I

    move-result v1

    aget-object v0, v0, v1

    if-eqz v0, :cond_2

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yna;->OooO0o(Llyiahf/vczjk/x04;)V

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/yna;->OooO0O0:[Llyiahf/vczjk/x04;

    const/16 v1, 0x20

    invoke-static {v1}, Llyiahf/vczjk/ll6;->OooO0oo(I)I

    move-result v1

    aget-object v0, v0, v1

    if-eqz v0, :cond_3

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yna;->OooO0Oo(Llyiahf/vczjk/x04;)V

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/yna;->OooO0O0:[Llyiahf/vczjk/x04;

    const/16 v1, 0x40

    invoke-static {v1}, Llyiahf/vczjk/ll6;->OooO0oo(I)I

    move-result v1

    aget-object v0, v0, v1

    if-eqz v0, :cond_4

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yna;->OooO0oo(Llyiahf/vczjk/x04;)V

    :cond_4
    return-void
.end method

.method public abstract OooO0O0()Llyiahf/vczjk/ioa;
.end method

.method public OooO0OO(ILlyiahf/vczjk/x04;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/yna;->OooO0O0:[Llyiahf/vczjk/x04;

    if-nez v0, :cond_0

    const/16 v0, 0xa

    new-array v0, v0, [Llyiahf/vczjk/x04;

    iput-object v0, p0, Llyiahf/vczjk/yna;->OooO0O0:[Llyiahf/vczjk/x04;

    :cond_0
    const/4 v0, 0x1

    :goto_0
    const/16 v1, 0x200

    if-gt v0, v1, :cond_2

    and-int v1, p1, v0

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/yna;->OooO0O0:[Llyiahf/vczjk/x04;

    invoke-static {v0}, Llyiahf/vczjk/ll6;->OooO0oo(I)I

    move-result v2

    aput-object p2, v1, v2

    :goto_1
    shl-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public OooO0Oo(Llyiahf/vczjk/x04;)V
    .locals 0

    return-void
.end method

.method public OooO0o(Llyiahf/vczjk/x04;)V
    .locals 0

    return-void
.end method

.method public abstract OooO0o0(Llyiahf/vczjk/x04;)V
.end method

.method public abstract OooO0oO(Llyiahf/vczjk/x04;)V
.end method

.method public OooO0oo(Llyiahf/vczjk/x04;)V
    .locals 0

    return-void
.end method
