.class public final Llyiahf/vczjk/kf;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_apply:Llyiahf/vczjk/zz6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zz6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kf;->$this_apply:Llyiahf/vczjk/zz6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v0, p1, Llyiahf/vczjk/b24;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/kf;->$this_apply:Llyiahf/vczjk/zz6;

    new-instance v2, Llyiahf/vczjk/b24;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zz6;->setPopupContentSize-fhxjrPA(Llyiahf/vczjk/b24;)V

    iget-object p1, p0, Llyiahf/vczjk/kf;->$this_apply:Llyiahf/vczjk/zz6;

    invoke-virtual {p1}, Llyiahf/vczjk/zz6;->OooOOO()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
