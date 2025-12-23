.class public final Llyiahf/vczjk/jpa;
.super Landroid/database/ContentObserver;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/jj0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jj0;Landroid/os/Handler;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jpa;->OooO00o:Llyiahf/vczjk/jj0;

    invoke-direct {p0, p2}, Landroid/database/ContentObserver;-><init>(Landroid/os/Handler;)V

    return-void
.end method


# virtual methods
.method public final onChange(ZLandroid/net/Uri;)V
    .locals 0

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object p2, p0, Llyiahf/vczjk/jpa;->OooO00o:Llyiahf/vczjk/jj0;

    invoke-interface {p2, p1}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
