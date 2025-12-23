.class public final Llyiahf/vczjk/e67;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Lnow/fortuitous/thanos/process/v2/RunningAppState;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/t67;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;


# direct methods
.method public synthetic constructor <init>(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/t67;Llyiahf/vczjk/oe3;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/e67;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/e67;->OooOOO:Lnow/fortuitous/thanos/process/v2/RunningAppState;

    iput-object p2, p0, Llyiahf/vczjk/e67;->OooOOOO:Llyiahf/vczjk/t67;

    iput-object p3, p0, Llyiahf/vczjk/e67;->OooOOOo:Llyiahf/vczjk/oe3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/e67;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/vk;

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    const-string p2, "$this$AnimatedVisibility"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/e67;->OooOOOO:Llyiahf/vczjk/t67;

    iget-object p2, p1, Llyiahf/vczjk/t67;->OooO0oO:Ljava/util/Map;

    iget-object v0, p0, Llyiahf/vczjk/e67;->OooOOO:Lnow/fortuitous/thanos/process/v2/RunningAppState;

    iget-object p3, v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-interface {p2, p3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    move-object v1, p2

    check-cast v1, Ljava/lang/String;

    iget-object p2, v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object p1, p1, Llyiahf/vczjk/t67;->OooO0oo:Ljava/util/Map;

    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/rz5;

    iget-object v3, p0, Llyiahf/vczjk/e67;->OooOOOo:Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/xt6;->OooOOO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Ljava/lang/String;Llyiahf/vczjk/rz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/vk;

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    const-string p2, "$this$AnimatedVisibility"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/e67;->OooOOOO:Llyiahf/vczjk/t67;

    iget-object p2, p1, Llyiahf/vczjk/t67;->OooO0oO:Ljava/util/Map;

    iget-object v0, p0, Llyiahf/vczjk/e67;->OooOOO:Lnow/fortuitous/thanos/process/v2/RunningAppState;

    iget-object p3, v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-interface {p2, p3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    move-object v1, p2

    check-cast v1, Ljava/lang/String;

    iget-object p2, v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object p1, p1, Llyiahf/vczjk/t67;->OooO0oo:Ljava/util/Map;

    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/rz5;

    iget-object v3, p0, Llyiahf/vczjk/e67;->OooOOOo:Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/xt6;->OooOOO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Ljava/lang/String;Llyiahf/vczjk/rz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
