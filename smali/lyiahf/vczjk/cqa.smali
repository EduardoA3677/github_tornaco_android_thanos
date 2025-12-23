.class public abstract Llyiahf/vczjk/cqa;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-string v0, "WorkConstraintsTracker"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "tagWithPrefix(\"WorkConstraintsTracker\")"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/cqa;->OooO00o:Ljava/lang/String;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/qr1;Llyiahf/vczjk/pa6;)Llyiahf/vczjk/r09;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "dispatcher"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "listener"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/bqa;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, p3, v1}, Llyiahf/vczjk/bqa;-><init>(Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/pa6;Llyiahf/vczjk/yo1;)V

    const/4 p0, 0x3

    invoke-static {p2, v1, v1, v0, p0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p0

    return-object p0
.end method
