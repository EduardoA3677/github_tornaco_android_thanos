.class public final Lnow/fortuitous/secure/ops/AppOpsService$monitor$1;
.super Lnow/fortuitous/pm/PackageMonitor;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\n\u0018\u00002\u00020\u0001\u00a8\u0006\u0002"
    }
    d2 = {
        "now/fortuitous/secure/ops/AppOpsService$monitor$1",
        "Lnow/fortuitous/pm/PackageMonitor;",
        "services"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final synthetic OooOO0O:I


# instance fields
.field public final synthetic OooOO0:Llyiahf/vczjk/fw;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fw;)V
    .locals 0

    iput-object p1, p0, Lnow/fortuitous/secure/ops/AppOpsService$monitor$1;->OooOO0:Llyiahf/vczjk/fw;

    invoke-direct {p0}, Lnow/fortuitous/pm/PackageMonitor;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0OO(ILjava/lang/String;)V
    .locals 2

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "onPackageRemoved: "

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, ", rest it\'s ops."

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/oO0oO000;

    iget-object v0, p0, Lnow/fortuitous/secure/ops/AppOpsService$monitor$1;->OooOO0:Llyiahf/vczjk/fw;

    const/16 v1, 0xe

    invoke-direct {p1, v1, v0, p2}, Llyiahf/vczjk/oO0oO000;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void
.end method
