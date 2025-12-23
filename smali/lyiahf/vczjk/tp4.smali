.class public final Llyiahf/vczjk/tp4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $columns:Llyiahf/vczjk/ak3;

.field final synthetic $horizontalArrangement:Llyiahf/vczjk/nx;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ak3;Llyiahf/vczjk/nx;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tp4;->$columns:Llyiahf/vczjk/ak3;

    iput-object p2, p0, Llyiahf/vczjk/tp4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/f62;

    check-cast p2, Llyiahf/vczjk/rk1;

    iget-wide p1, p2, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-static {p1, p2}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v0

    const v2, 0x7fffffff

    if-eq v0, v2, :cond_0

    goto :goto_0

    :cond_0
    const-string v0, "LazyVerticalGrid\'s width should be bound by parent."

    invoke-static {v0}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    invoke-static {p1, p2}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v2

    iget-object p1, p0, Llyiahf/vczjk/tp4;->$columns:Llyiahf/vczjk/ak3;

    iget-object v0, p0, Llyiahf/vczjk/tp4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    invoke-interface {v0}, Llyiahf/vczjk/nx;->OooO0O0()F

    move-result p2

    invoke-interface {v1, p2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p2

    invoke-interface {p1, v1, v2, p2}, Llyiahf/vczjk/ak3;->OooO00o(Llyiahf/vczjk/f62;II)Ljava/util/ArrayList;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0000O0O(Ljava/util/List;)[I

    move-result-object v3

    array-length p1, v3

    new-array v5, p1, [I

    sget-object v4, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/nx;->OooO0o0(Llyiahf/vczjk/f62;I[ILlyiahf/vczjk/yn4;[I)V

    new-instance p1, Llyiahf/vczjk/n62;

    const/16 p2, 0x14

    const/4 v0, 0x0

    invoke-direct {p1, p2, v3, v5, v0}, Llyiahf/vczjk/n62;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    return-object p1
.end method
