.class public final Llyiahf/vczjk/lt8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $a11yPaneTitle:Ljava/lang/String;

.field final synthetic $isVisible:Z

.field final synthetic $key:Llyiahf/vczjk/ht8;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/lt8;->$isVisible:Z

    iput-object p1, p0, Llyiahf/vczjk/lt8;->$a11yPaneTitle:Ljava/lang/String;

    invoke-direct {p0, v0}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/af8;

    iget-boolean v0, p0, Llyiahf/vczjk/lt8;->$isVisible:Z

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v0, Llyiahf/vczjk/ve8;->OooOO0:Llyiahf/vczjk/ze8;

    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v2, 0x3

    aget-object v1, v1, v2

    new-instance v1, Llyiahf/vczjk/n25;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/lt8;->$a11yPaneTitle:Ljava/lang/String;

    invoke-static {p1, v0}, Llyiahf/vczjk/ye8;->OooO0o0(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/kt8;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/rm4;-><init>(I)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooOo0:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
