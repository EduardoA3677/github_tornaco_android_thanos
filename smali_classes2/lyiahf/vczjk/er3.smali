.class public final Llyiahf/vczjk/er3;
.super Llyiahf/vczjk/fr3;
.source "SourceFile"


# instance fields
.field public final OooO0Oo:Llyiahf/vczjk/yn0;

.field public final OooO0o0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ir7;Llyiahf/vczjk/vn0;Llyiahf/vczjk/fp1;Llyiahf/vczjk/yn0;Z)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/fr3;-><init>(Llyiahf/vczjk/ir7;Llyiahf/vczjk/vn0;Llyiahf/vczjk/fp1;)V

    iput-object p4, p0, Llyiahf/vczjk/er3;->OooO0Oo:Llyiahf/vczjk/yn0;

    iput-boolean p5, p0, Llyiahf/vczjk/er3;->OooO0o0:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/c96;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er3;->OooO0Oo:Llyiahf/vczjk/yn0;

    invoke-interface {v0, p1}, Llyiahf/vczjk/yn0;->OoooOO0(Llyiahf/vczjk/c96;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wn0;

    array-length v0, p2

    add-int/lit8 v0, v0, -0x1

    aget-object p2, p2, v0

    check-cast p2, Llyiahf/vczjk/yo1;

    :try_start_0
    iget-boolean v0, p0, Llyiahf/vczjk/er3;->OooO0o0:Z

    if-eqz v0, :cond_0

    const-string v0, "null cannot be cast to non-null type retrofit2.Call<kotlin.Unit?>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1, p2}, Llyiahf/vczjk/so8;->OooOOOo(Llyiahf/vczjk/wn0;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-static {p1, p2}, Llyiahf/vczjk/so8;->OooOOOO(Llyiahf/vczjk/wn0;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/VirtualMachineError; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/ThreadDeath; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/LinkageError; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p1

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    goto :goto_1

    :catch_1
    move-exception p1

    goto :goto_1

    :catch_2
    move-exception p1

    goto :goto_1

    :goto_0
    invoke-static {p1, p2}, Llyiahf/vczjk/so8;->OoooO00(Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1

    :goto_1
    throw p1
.end method
