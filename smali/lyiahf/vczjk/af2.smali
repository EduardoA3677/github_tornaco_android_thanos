.class public final Llyiahf/vczjk/af2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $velocityTracker:Llyiahf/vczjk/hea;

.field final synthetic this$0:Llyiahf/vczjk/kf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/hea;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/af2;->$velocityTracker:Llyiahf/vczjk/hea;

    iput-object p1, p0, Llyiahf/vczjk/af2;->this$0:Llyiahf/vczjk/kf2;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/ky6;

    check-cast p2, Llyiahf/vczjk/p86;

    iget-wide v0, p2, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p2, p0, Llyiahf/vczjk/af2;->$velocityTracker:Llyiahf/vczjk/hea;

    invoke-static {p2, p1}, Llyiahf/vczjk/ok6;->OooOOOo(Llyiahf/vczjk/hea;Llyiahf/vczjk/ky6;)V

    iget-object p1, p0, Llyiahf/vczjk/af2;->this$0:Llyiahf/vczjk/kf2;

    iget-object p1, p1, Llyiahf/vczjk/kf2;->Oooo00O:Llyiahf/vczjk/jj0;

    if-eqz p1, :cond_0

    new-instance p2, Llyiahf/vczjk/ke2;

    invoke-direct {p2, v0, v1}, Llyiahf/vczjk/ke2;-><init>(J)V

    invoke-interface {p1, p2}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
