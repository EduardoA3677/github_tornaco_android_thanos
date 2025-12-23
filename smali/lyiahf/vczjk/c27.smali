.class public final Llyiahf/vczjk/c27;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ay1;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ay1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ay1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/c27;->OooO00o:Llyiahf/vczjk/ay1;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/b27;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/b27;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iget-object p1, p0, Llyiahf/vczjk/c27;->OooO00o:Llyiahf/vczjk/ay1;

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/ay1;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final getData()Llyiahf/vczjk/f43;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/c27;->OooO00o:Llyiahf/vczjk/ay1;

    invoke-interface {v0}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object v0

    return-object v0
.end method
