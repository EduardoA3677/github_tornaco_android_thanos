.class public final Llyiahf/vczjk/t05;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lf5;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/le3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t05;->OooO00o:Llyiahf/vczjk/le3;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;
    .locals 1

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p3

    new-instance p4, Llyiahf/vczjk/s05;

    invoke-direct {p4, p2, p0}, Llyiahf/vczjk/s05;-><init>(Ljava/util/List;Llyiahf/vczjk/t05;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, v0, p3, p2, p4}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
