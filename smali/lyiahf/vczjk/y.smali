.class public final Llyiahf/vczjk/y;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $activityResultRegistry:Llyiahf/vczjk/w;

.field final synthetic $contract:Llyiahf/vczjk/m;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/m;"
        }
    .end annotation
.end field

.field final synthetic $currentOnResult:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $key:Ljava/lang/String;

.field final synthetic $realLauncher:Llyiahf/vczjk/q;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/q;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q;Llyiahf/vczjk/w;Ljava/lang/String;Llyiahf/vczjk/n;Llyiahf/vczjk/qs5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/y;->$realLauncher:Llyiahf/vczjk/q;

    iput-object p2, p0, Llyiahf/vczjk/y;->$activityResultRegistry:Llyiahf/vczjk/w;

    iput-object p3, p0, Llyiahf/vczjk/y;->$key:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/y;->$contract:Llyiahf/vczjk/m;

    iput-object p5, p0, Llyiahf/vczjk/y;->$currentOnResult:Llyiahf/vczjk/p29;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/y;->$realLauncher:Llyiahf/vczjk/q;

    iget-object v0, p0, Llyiahf/vczjk/y;->$activityResultRegistry:Llyiahf/vczjk/w;

    iget-object v1, p0, Llyiahf/vczjk/y;->$key:Ljava/lang/String;

    iget-object v2, p0, Llyiahf/vczjk/y;->$contract:Llyiahf/vczjk/m;

    iget-object v3, p0, Llyiahf/vczjk/y;->$currentOnResult:Llyiahf/vczjk/p29;

    new-instance v4, Llyiahf/vczjk/oOO000o;

    const/4 v5, 0x2

    invoke-direct {v4, v3, v5}, Llyiahf/vczjk/oOO000o;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v0, v1, v2, v4}, Llyiahf/vczjk/w;->OooO0OO(Ljava/lang/String;Llyiahf/vczjk/m;Llyiahf/vczjk/l;)Llyiahf/vczjk/v;

    move-result-object v0

    iput-object v0, p1, Llyiahf/vczjk/q;->OooO00o:Llyiahf/vczjk/v;

    iget-object p1, p0, Llyiahf/vczjk/y;->$realLauncher:Llyiahf/vczjk/q;

    new-instance v0, Llyiahf/vczjk/x;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/x;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method
