.class public final Llyiahf/vczjk/w70;
.super Lgithub/tornaco/android/thanos/core/app/infinite/RemovePackageCallback;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o:Llyiahf/vczjk/qy3;

.field public final synthetic OooO0o0:Llyiahf/vczjk/py3;

.field public final synthetic OooO0oO:Llyiahf/vczjk/x70;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x70;Llyiahf/vczjk/py3;Llyiahf/vczjk/qy3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/w70;->OooO0oO:Llyiahf/vczjk/x70;

    iput-object p2, p0, Llyiahf/vczjk/w70;->OooO0o0:Llyiahf/vczjk/py3;

    iput-object p3, p0, Llyiahf/vczjk/w70;->OooO0o:Llyiahf/vczjk/qy3;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/app/infinite/RemovePackageCallback;-><init>()V

    return-void
.end method


# virtual methods
.method public final onErrorMain(Ljava/lang/String;I)V
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/w70;->OooO0o:Llyiahf/vczjk/qy3;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/qy3;->accept(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/w70;->OooO0oO:Llyiahf/vczjk/x70;

    invoke-virtual {p1}, Llyiahf/vczjk/x70;->OooO0oO()V

    return-void
.end method

.method public final onSuccessMain()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w70;->OooO0o0:Llyiahf/vczjk/py3;

    invoke-virtual {v0}, Llyiahf/vczjk/py3;->run()V

    iget-object v0, p0, Llyiahf/vczjk/w70;->OooO0oO:Llyiahf/vczjk/x70;

    invoke-virtual {v0}, Llyiahf/vczjk/x70;->OooO0oO()V

    return-void
.end method
