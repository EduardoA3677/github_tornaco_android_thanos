.class public final Llyiahf/vczjk/qm9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $range:Llyiahf/vczjk/zm;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zm;"
        }
    .end annotation
.end field

.field final synthetic $uriHandler:Llyiahf/vczjk/raa;

.field final synthetic this$0:Llyiahf/vczjk/zm9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zm9;Llyiahf/vczjk/zm;Llyiahf/vczjk/raa;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qm9;->this$0:Llyiahf/vczjk/zm9;

    iput-object p2, p0, Llyiahf/vczjk/qm9;->$range:Llyiahf/vczjk/zm;

    iput-object p3, p0, Llyiahf/vczjk/qm9;->$uriHandler:Llyiahf/vczjk/raa;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/qm9;->this$0:Llyiahf/vczjk/zm9;

    iget-object v1, p0, Llyiahf/vczjk/qm9;->$range:Llyiahf/vczjk/zm;

    iget-object v1, v1, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/e05;

    iget-object v2, p0, Llyiahf/vczjk/qm9;->$uriHandler:Llyiahf/vczjk/raa;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, v1, Llyiahf/vczjk/d05;

    if-eqz v0, :cond_0

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :try_start_0
    check-cast v1, Llyiahf/vczjk/d05;

    iget-object v0, v1, Llyiahf/vczjk/d05;->OooO00o:Ljava/lang/String;

    check-cast v2, Llyiahf/vczjk/xg;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/xg;->OooO00o(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :cond_0
    instance-of v0, v1, Llyiahf/vczjk/c05;

    if-eqz v0, :cond_1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :catch_0
    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
