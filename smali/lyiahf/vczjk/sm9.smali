.class public final Llyiahf/vczjk/sm9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $linkStateObserver:Llyiahf/vczjk/i05;

.field final synthetic $range:Llyiahf/vczjk/zm;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zm;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/zm9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zm9;Llyiahf/vczjk/zm;Llyiahf/vczjk/i05;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sm9;->this$0:Llyiahf/vczjk/zm9;

    iput-object p2, p0, Llyiahf/vczjk/sm9;->$range:Llyiahf/vczjk/zm;

    iput-object p3, p0, Llyiahf/vczjk/sm9;->$linkStateObserver:Llyiahf/vczjk/i05;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/nh9;

    iget-object v0, p0, Llyiahf/vczjk/sm9;->this$0:Llyiahf/vczjk/zm9;

    iget-object v1, p0, Llyiahf/vczjk/sm9;->$range:Llyiahf/vczjk/zm;

    iget-object v1, v1, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/e05;

    invoke-virtual {v1}, Llyiahf/vczjk/e05;->OooO00o()Llyiahf/vczjk/an9;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    iget-object v1, v1, Llyiahf/vczjk/an9;->OooO00o:Llyiahf/vczjk/dy8;

    goto :goto_0

    :cond_0
    move-object v1, v2

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/sm9;->$linkStateObserver:Llyiahf/vczjk/i05;

    iget-object v3, v3, Llyiahf/vczjk/i05;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v3, Llyiahf/vczjk/bw8;

    invoke-virtual {v3}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v3

    and-int/lit8 v3, v3, 0x1

    if-eqz v3, :cond_1

    iget-object v3, p0, Llyiahf/vczjk/sm9;->$range:Llyiahf/vczjk/zm;

    iget-object v3, v3, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/e05;

    invoke-virtual {v3}, Llyiahf/vczjk/e05;->OooO00o()Llyiahf/vczjk/an9;

    move-result-object v3

    if-eqz v3, :cond_1

    iget-object v3, v3, Llyiahf/vczjk/an9;->OooO0O0:Llyiahf/vczjk/dy8;

    goto :goto_1

    :cond_1
    move-object v3, v2

    :goto_1
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz v1, :cond_2

    invoke-virtual {v1, v3}, Llyiahf/vczjk/dy8;->OooO0OO(Llyiahf/vczjk/dy8;)Llyiahf/vczjk/dy8;

    move-result-object v3

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/sm9;->$linkStateObserver:Llyiahf/vczjk/i05;

    iget-object v0, v0, Llyiahf/vczjk/i05;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    and-int/lit8 v0, v0, 0x2

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/sm9;->$range:Llyiahf/vczjk/zm;

    iget-object v0, v0, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/e05;

    invoke-virtual {v0}, Llyiahf/vczjk/e05;->OooO00o()Llyiahf/vczjk/an9;

    move-result-object v0

    if-eqz v0, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/an9;->OooO0OO:Llyiahf/vczjk/dy8;

    goto :goto_2

    :cond_3
    move-object v0, v2

    :goto_2
    if-eqz v3, :cond_4

    invoke-virtual {v3, v0}, Llyiahf/vczjk/dy8;->OooO0OO(Llyiahf/vczjk/dy8;)Llyiahf/vczjk/dy8;

    move-result-object v0

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/sm9;->$linkStateObserver:Llyiahf/vczjk/i05;

    iget-object v1, v1, Llyiahf/vczjk/i05;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v1

    and-int/lit8 v1, v1, 0x4

    if-eqz v1, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/sm9;->$range:Llyiahf/vczjk/zm;

    iget-object v1, v1, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/e05;

    invoke-virtual {v1}, Llyiahf/vczjk/e05;->OooO00o()Llyiahf/vczjk/an9;

    move-result-object v1

    if-eqz v1, :cond_5

    iget-object v2, v1, Llyiahf/vczjk/an9;->OooO0Oo:Llyiahf/vczjk/dy8;

    :cond_5
    if-eqz v0, :cond_6

    invoke-virtual {v0, v2}, Llyiahf/vczjk/dy8;->OooO0OO(Llyiahf/vczjk/dy8;)Llyiahf/vczjk/dy8;

    move-result-object v2

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/sm9;->$range:Llyiahf/vczjk/zm;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/dl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    new-instance v3, Llyiahf/vczjk/mh9;

    invoke-direct {v3, v1, v0, v2}, Llyiahf/vczjk/mh9;-><init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/zm;Llyiahf/vczjk/dy8;)V

    iget-object v0, p1, Llyiahf/vczjk/nh9;->OooO00o:Llyiahf/vczjk/an;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/an;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/an;

    move-result-object v0

    iput-object v0, p1, Llyiahf/vczjk/nh9;->OooO0O0:Llyiahf/vczjk/an;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
