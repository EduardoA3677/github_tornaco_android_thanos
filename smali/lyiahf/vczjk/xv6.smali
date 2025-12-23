.class public final synthetic Llyiahf/vczjk/xv6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Llyiahf/vczjk/cf3;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZLlyiahf/vczjk/cf3;II)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/xv6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/xv6;->OooOOOO:Ljava/lang/Object;

    iput-boolean p2, p0, Llyiahf/vczjk/xv6;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/xv6;->OooOOOo:Llyiahf/vczjk/cf3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/xv6;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    packed-switch v0, :pswitch_data_0

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-boolean v0, p0, Llyiahf/vczjk/xv6;->OooOOO:Z

    iget-object v1, p0, Llyiahf/vczjk/xv6;->OooOOOo:Llyiahf/vczjk/cf3;

    check-cast v1, Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/xv6;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/uh6;

    invoke-static {v2, v0, v1, p1, p2}, Llyiahf/vczjk/xt6;->OooO0OO(Llyiahf/vczjk/uh6;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-boolean v0, p0, Llyiahf/vczjk/xv6;->OooOOO:Z

    iget-object v1, p0, Llyiahf/vczjk/xv6;->OooOOOo:Llyiahf/vczjk/cf3;

    check-cast v1, Llyiahf/vczjk/ze3;

    iget-object v2, p0, Llyiahf/vczjk/xv6;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v2, v0, v1, p1, p2}, Llyiahf/vczjk/ok6;->OooO0OO(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
