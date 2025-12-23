.class public final Llyiahf/vczjk/ej;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $currentlyVisible:Llyiahf/vczjk/tw8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/tw8;"
        }
    .end annotation
.end field

.field final synthetic $rootScope:Llyiahf/vczjk/uj;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/uj;"
        }
    .end annotation
.end field

.field final synthetic $stateForContent:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tw8;Ljava/lang/Object;Llyiahf/vczjk/uj;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ej;->$currentlyVisible:Llyiahf/vczjk/tw8;

    iput-object p2, p0, Llyiahf/vczjk/ej;->$stateForContent:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/ej;->$rootScope:Llyiahf/vczjk/uj;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/ej;->$currentlyVisible:Llyiahf/vczjk/tw8;

    iget-object v0, p0, Llyiahf/vczjk/ej;->$stateForContent:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/ej;->$rootScope:Llyiahf/vczjk/uj;

    new-instance v2, Llyiahf/vczjk/o0OO0;

    const/4 v3, 0x1

    invoke-direct {v2, p1, v0, v3, v1}, Llyiahf/vczjk/o0OO0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    return-object v2
.end method
