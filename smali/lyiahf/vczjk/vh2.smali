.class public final Llyiahf/vczjk/vh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $closeDrawer:Ljava/lang/String;

.field final synthetic $onClose:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/le3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vh2;->$closeDrawer:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/vh2;->$onClose:Llyiahf/vczjk/le3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/af8;

    iget-object v0, p0, Llyiahf/vczjk/vh2;->$closeDrawer:Ljava/lang/String;

    invoke-static {p1, v0}, Llyiahf/vczjk/ye8;->OooO0Oo(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/uh2;

    iget-object v1, p0, Llyiahf/vczjk/vh2;->$onClose:Llyiahf/vczjk/le3;

    invoke-direct {v0, v1}, Llyiahf/vczjk/uh2;-><init>(Llyiahf/vczjk/le3;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooO0O0:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
