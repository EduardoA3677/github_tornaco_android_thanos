.class public final Llyiahf/vczjk/qi;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $channel:Llyiahf/vczjk/rs0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/rs0;"
        }
    .end annotation
.end field

.field final synthetic $targetValue:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rs0;Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qi;->$channel:Llyiahf/vczjk/rs0;

    iput-object p2, p0, Llyiahf/vczjk/qi;->$targetValue:Ljava/lang/Object;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/qi;->$channel:Llyiahf/vczjk/rs0;

    iget-object v1, p0, Llyiahf/vczjk/qi;->$targetValue:Ljava/lang/Object;

    invoke-interface {v0, v1}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
