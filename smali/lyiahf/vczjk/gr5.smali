.class public final Llyiahf/vczjk/gr5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $remote:Z

.field final synthetic $state:Llyiahf/vczjk/q25;

.field final synthetic $type:Llyiahf/vczjk/s25;

.field final synthetic this$0:Llyiahf/vczjk/hr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/s25;Llyiahf/vczjk/hr5;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/p25;->OooO0OO:Llyiahf/vczjk/p25;

    const/4 v1, 0x0

    iput-boolean v1, p0, Llyiahf/vczjk/gr5;->$remote:Z

    iput-object p1, p0, Llyiahf/vczjk/gr5;->$type:Llyiahf/vczjk/s25;

    iput-object v0, p0, Llyiahf/vczjk/gr5;->$state:Llyiahf/vczjk/q25;

    iput-object p2, p0, Llyiahf/vczjk/gr5;->this$0:Llyiahf/vczjk/hr5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/k41;

    if-eqz p1, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/k41;->OooO0Oo:Llyiahf/vczjk/r25;

    if-nez v0, :cond_1

    :cond_0
    sget-object v0, Llyiahf/vczjk/r25;->OooO0Oo:Llyiahf/vczjk/r25;

    :cond_1
    if-eqz p1, :cond_2

    iget-object v1, p1, Llyiahf/vczjk/k41;->OooO0o0:Llyiahf/vczjk/r25;

    goto :goto_0

    :cond_2
    const/4 v1, 0x0

    :goto_0
    iget-boolean v2, p0, Llyiahf/vczjk/gr5;->$remote:Z

    if-eqz v2, :cond_3

    sget-object v1, Llyiahf/vczjk/r25;->OooO0Oo:Llyiahf/vczjk/r25;

    iget-object v2, p0, Llyiahf/vczjk/gr5;->$type:Llyiahf/vczjk/s25;

    iget-object v3, p0, Llyiahf/vczjk/gr5;->$state:Llyiahf/vczjk/q25;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/r25;->OooO0O0(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)Llyiahf/vczjk/r25;

    move-result-object v1

    goto :goto_1

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/gr5;->$type:Llyiahf/vczjk/s25;

    iget-object v3, p0, Llyiahf/vczjk/gr5;->$state:Llyiahf/vczjk/q25;

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/r25;->OooO0O0(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)Llyiahf/vczjk/r25;

    move-result-object v0

    :goto_1
    iget-object v2, p0, Llyiahf/vczjk/gr5;->this$0:Llyiahf/vczjk/hr5;

    invoke-static {v2, p1, v0, v1}, Llyiahf/vczjk/hr5;->OooO00o(Llyiahf/vczjk/hr5;Llyiahf/vczjk/k41;Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)Llyiahf/vczjk/k41;

    move-result-object p1

    return-object p1
.end method
