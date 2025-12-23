.class public final Llyiahf/vczjk/us;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ws;


# instance fields
.field public final synthetic OooO00o:Lnow/fortuitous/thanos/apps/AppDetailsActivity;


# direct methods
.method public constructor <init>(Lnow/fortuitous/thanos/apps/AppDetailsActivity;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/us;->OooO00o:Lnow/fortuitous/thanos/apps/AppDetailsActivity;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/String;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/kd5;

    iget-object v1, p0, Llyiahf/vczjk/us;->OooO00o:Lnow/fortuitous/thanos/apps/AppDetailsActivity;

    invoke-direct {v0, v1}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    iget-object v2, v0, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s3;

    iput-object p1, v2, Llyiahf/vczjk/s3;->OooO0o:Ljava/lang/CharSequence;

    const/4 p1, 0x1

    iput-boolean p1, v2, Llyiahf/vczjk/s3;->OooOOO0:Z

    const p1, 0x104000a

    const/4 v2, 0x0

    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {v0}, Llyiahf/vczjk/w3;->OooOOOO()Llyiahf/vczjk/x3;

    iget-object p1, v1, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OoooO00:Llyiahf/vczjk/dl5;

    invoke-virtual {p1}, Llyiahf/vczjk/dl5;->OooO00o()V

    return-void
.end method
