.class public final Llyiahf/vczjk/fr5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $remoteLoadStates:Llyiahf/vczjk/r25;

.field final synthetic $sourceLoadStates:Llyiahf/vczjk/r25;

.field final synthetic this$0:Llyiahf/vczjk/hr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hr5;Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fr5;->this$0:Llyiahf/vczjk/hr5;

    iput-object p2, p0, Llyiahf/vczjk/fr5;->$sourceLoadStates:Llyiahf/vczjk/r25;

    iput-object p3, p0, Llyiahf/vczjk/fr5;->$remoteLoadStates:Llyiahf/vczjk/r25;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/k41;

    iget-object v0, p0, Llyiahf/vczjk/fr5;->this$0:Llyiahf/vczjk/hr5;

    iget-object v1, p0, Llyiahf/vczjk/fr5;->$sourceLoadStates:Llyiahf/vczjk/r25;

    iget-object v2, p0, Llyiahf/vczjk/fr5;->$remoteLoadStates:Llyiahf/vczjk/r25;

    invoke-static {v0, p1, v1, v2}, Llyiahf/vczjk/hr5;->OooO00o(Llyiahf/vczjk/hr5;Llyiahf/vczjk/k41;Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)Llyiahf/vczjk/k41;

    move-result-object p1

    return-object p1
.end method
