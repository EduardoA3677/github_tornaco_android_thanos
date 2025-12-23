.class public final Llyiahf/vczjk/ej1;
.super Lgithub/tornaco/android/thanos/core/profile/LogSink;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/fj1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fj1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ej1;->OooO00o:Llyiahf/vczjk/fj1;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/profile/LogSink;-><init>()V

    return-void
.end method


# virtual methods
.method public final log(Ljava/lang/String;)V
    .locals 4

    invoke-super {p0, p1}, Lgithub/tornaco/android/thanos/core/profile/LogSink;->log(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ej1;->OooO00o:Llyiahf/vczjk/fj1;

    iget-object v0, v0, Llyiahf/vczjk/fj1;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/dj1;

    if-nez p1, :cond_0

    const-string p1, "null"

    :cond_0
    const/4 v2, 0x0

    const/4 v3, 0x1

    invoke-static {v1, v2, p1, v3}, Llyiahf/vczjk/dj1;->OooO00o(Llyiahf/vczjk/dj1;Ljava/lang/String;Ljava/lang/String;I)Llyiahf/vczjk/dj1;

    move-result-object p1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v2, p1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    return-void
.end method
