.class public final Llyiahf/vczjk/df2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $velocityTracker:Llyiahf/vczjk/hea;

.field final synthetic this$0:Llyiahf/vczjk/kf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/hea;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/df2;->this$0:Llyiahf/vczjk/kf2;

    iput-object p2, p0, Llyiahf/vczjk/df2;->$velocityTracker:Llyiahf/vczjk/hea;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/ky6;

    check-cast p2, Llyiahf/vczjk/ky6;

    check-cast p3, Llyiahf/vczjk/p86;

    iget-wide v0, p3, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p3, p0, Llyiahf/vczjk/df2;->this$0:Llyiahf/vczjk/kf2;

    iget-object p3, p3, Llyiahf/vczjk/kf2;->OooOooO:Llyiahf/vczjk/rm4;

    invoke-interface {p3, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/Boolean;

    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p3

    if-eqz p3, :cond_2

    iget-object p3, p0, Llyiahf/vczjk/df2;->this$0:Llyiahf/vczjk/kf2;

    iget-boolean v2, p3, Llyiahf/vczjk/kf2;->Oooo0:Z

    if-nez v2, :cond_1

    iget-object v2, p3, Llyiahf/vczjk/kf2;->Oooo00O:Llyiahf/vczjk/jj0;

    const/4 v3, 0x0

    if-nez v2, :cond_0

    const v2, 0x7fffffff

    const/4 v4, 0x6

    invoke-static {v2, v4, v3}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v2

    iput-object v2, p3, Llyiahf/vczjk/kf2;->Oooo00O:Llyiahf/vczjk/jj0;

    :cond_0
    iget-object p3, p0, Llyiahf/vczjk/df2;->this$0:Llyiahf/vczjk/kf2;

    const/4 v2, 0x1

    iput-boolean v2, p3, Llyiahf/vczjk/kf2;->Oooo0:Z

    invoke-virtual {p3}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v2

    new-instance v4, Llyiahf/vczjk/jf2;

    invoke-direct {v4, p3, v3}, Llyiahf/vczjk/jf2;-><init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/yo1;)V

    const/4 p3, 0x3

    invoke-static {v2, v3, v3, v4, p3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_1
    iget-object p3, p0, Llyiahf/vczjk/df2;->$velocityTracker:Llyiahf/vczjk/hea;

    invoke-static {p3, p1}, Llyiahf/vczjk/ok6;->OooOOOo(Llyiahf/vczjk/hea;Llyiahf/vczjk/ky6;)V

    iget-wide p1, p2, Llyiahf/vczjk/ky6;->OooO0OO:J

    invoke-static {p1, p2, v0, v1}, Llyiahf/vczjk/p86;->OooO0o0(JJ)J

    move-result-wide p1

    iget-object p3, p0, Llyiahf/vczjk/df2;->this$0:Llyiahf/vczjk/kf2;

    iget-object p3, p3, Llyiahf/vczjk/kf2;->Oooo00O:Llyiahf/vczjk/jj0;

    if-eqz p3, :cond_2

    new-instance v0, Llyiahf/vczjk/le2;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/le2;-><init>(J)V

    invoke-interface {p3, v0}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
