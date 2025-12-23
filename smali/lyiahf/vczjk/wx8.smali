.class public final Llyiahf/vczjk/wx8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rg1;
.implements Ljava/lang/Iterable;
.implements Llyiahf/vczjk/cg4;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:Llyiahf/vczjk/js8;

.field public final OooOOOO:Llyiahf/vczjk/do7;

.field public final OooOOOo:Ljava/lang/Integer;

.field public final OooOOo0:Llyiahf/vczjk/wx8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/js8;ILlyiahf/vczjk/ik3;Llyiahf/vczjk/do7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wx8;->OooOOO0:Llyiahf/vczjk/js8;

    iput p2, p0, Llyiahf/vczjk/wx8;->OooOOO:I

    iput-object p4, p0, Llyiahf/vczjk/wx8;->OooOOOO:Llyiahf/vczjk/do7;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wx8;->OooOOOo:Ljava/lang/Integer;

    iput-object p0, p0, Llyiahf/vczjk/wx8;->OooOOo0:Llyiahf/vczjk/wx8;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 1

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO0O0()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/wx8;->OooOOOO:Llyiahf/vczjk/do7;

    iget-object v1, p0, Llyiahf/vczjk/wx8;->OooOOO0:Llyiahf/vczjk/js8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/do7;->OooOOO0(Llyiahf/vczjk/js8;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0oo()Ljava/lang/Iterable;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wx8;->OooOOo0:Llyiahf/vczjk/wx8;

    return-object v0
.end method

.method public final getData()Ljava/lang/Iterable;
    .locals 4

    new-instance v0, Llyiahf/vczjk/vx8;

    iget v1, p0, Llyiahf/vczjk/wx8;->OooOOO:I

    const/4 v2, 0x0

    iget-object v3, p0, Llyiahf/vczjk/wx8;->OooOOO0:Llyiahf/vczjk/js8;

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/vx8;-><init>(Llyiahf/vczjk/js8;ILlyiahf/vczjk/ik3;)V

    return-object v0
.end method

.method public final getKey()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wx8;->OooOOOo:Ljava/lang/Integer;

    return-object v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 5

    new-instance v0, Llyiahf/vczjk/a62;

    iget-object v1, p0, Llyiahf/vczjk/wx8;->OooOOOO:Llyiahf/vczjk/do7;

    iget-object v2, p0, Llyiahf/vczjk/wx8;->OooOOO0:Llyiahf/vczjk/js8;

    iget v3, p0, Llyiahf/vczjk/wx8;->OooOOO:I

    const/4 v4, 0x0

    invoke-direct {v0, v2, v3, v4, v1}, Llyiahf/vczjk/a62;-><init>(Llyiahf/vczjk/js8;ILlyiahf/vczjk/ik3;Llyiahf/vczjk/fu6;)V

    return-object v0
.end method
