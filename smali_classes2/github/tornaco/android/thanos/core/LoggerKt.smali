.class public final Lgithub/tornaco/android/thanos/core/LoggerKt;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0008\u0007\":\u0010\u0004\u001a\u001a\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u00008\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0004\u0010\u0005\u001a\u0004\u0008\u0006\u0010\u0007\"\u0004\u0008\u0008\u0010\t\u00a8\u0006\n"
    }
    d2 = {
        "Lkotlin/Function3;",
        "",
        "",
        "Llyiahf/vczjk/z8a;",
        "logAdapter",
        "Llyiahf/vczjk/bf3;",
        "getLogAdapter",
        "()Llyiahf/vczjk/bf3;",
        "setLogAdapter",
        "(Llyiahf/vczjk/bf3;)V",
        "base"
    }
    k = 0x2
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field private static logAdapter:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/o0OO0O0;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/o0OO0O0;-><init>(I)V

    sput-object v0, Lgithub/tornaco/android/thanos/core/LoggerKt;->logAdapter:Llyiahf/vczjk/bf3;

    return-void
.end method

.method public static synthetic OooO00o(ILjava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/z8a;
    .locals 0

    invoke-static {p0, p1, p2}, Lgithub/tornaco/android/thanos/core/LoggerKt;->logAdapter$lambda$0(ILjava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p0

    return-object p0
.end method

.method public static final getLogAdapter()Llyiahf/vczjk/bf3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation

    sget-object v0, Lgithub/tornaco/android/thanos/core/LoggerKt;->logAdapter:Llyiahf/vczjk/bf3;

    return-object v0
.end method

.method private static final logAdapter$lambda$0(ILjava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/z8a;
    .locals 1

    const-string v0, "tag"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "msg"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1, p2}, Landroid/util/Log;->println(ILjava/lang/String;Ljava/lang/String;)I

    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static final setLogAdapter(Llyiahf/vczjk/bf3;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/bf3;",
            ")V"
        }
    .end annotation

    const-string v0, "<set-?>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sput-object p0, Lgithub/tornaco/android/thanos/core/LoggerKt;->logAdapter:Llyiahf/vczjk/bf3;

    return-void
.end method
