.class public final Llyiahf/vczjk/fga;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $lifecycle:Llyiahf/vczjk/ky4;

.field final synthetic $observer:Llyiahf/vczjk/sy4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/o0OO00o0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fga;->$lifecycle:Llyiahf/vczjk/ky4;

    iput-object p2, p0, Llyiahf/vczjk/fga;->$observer:Llyiahf/vczjk/sy4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fga;->$lifecycle:Llyiahf/vczjk/ky4;

    iget-object v1, p0, Llyiahf/vczjk/fga;->$observer:Llyiahf/vczjk/sy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
