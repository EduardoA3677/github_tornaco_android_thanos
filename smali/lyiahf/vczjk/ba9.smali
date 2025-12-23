.class public final Llyiahf/vczjk/ba9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/fi1;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/wg7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wg7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ba9;->OooOOO0:Llyiahf/vczjk/wg7;

    return-void
.end method


# virtual methods
.method public final OooOo00(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/ba9;->OooOOO0:Llyiahf/vczjk/wg7;

    iget-object p1, p1, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ea9;

    invoke-interface {p1}, Llyiahf/vczjk/ea9;->getDatabaseName()Ljava/lang/String;

    new-instance v0, Llyiahf/vczjk/ga9;

    new-instance v1, Llyiahf/vczjk/aa9;

    invoke-interface {p1}, Llyiahf/vczjk/ea9;->OoooOOO()Llyiahf/vczjk/ca9;

    move-result-object p1

    invoke-direct {v1, p1}, Llyiahf/vczjk/aa9;-><init>(Llyiahf/vczjk/ca9;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/ga9;-><init>(Llyiahf/vczjk/aa9;)V

    invoke-interface {p2, v0, p3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final close()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ba9;->OooOOO0:Llyiahf/vczjk/wg7;

    iget-object v0, v0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ea9;

    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    return-void
.end method
