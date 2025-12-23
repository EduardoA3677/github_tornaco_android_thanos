.class public abstract Llyiahf/vczjk/db9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/er5;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    const/4 v0, 0x0

    new-instance v1, Llyiahf/vczjk/er5;

    new-instance v2, Llyiahf/vczjk/dn2;

    sget-object v3, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    sget-object v3, Llyiahf/vczjk/uq2;->OooO0O0:Llyiahf/vczjk/iq2;

    sget-object v4, Llyiahf/vczjk/x09;->OooO0o:Llyiahf/vczjk/hc3;

    invoke-direct {v2, v3, v4, v0}, Llyiahf/vczjk/dn2;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;I)V

    sget-object v3, Llyiahf/vczjk/ly0;->OooOOO0:Llyiahf/vczjk/ly0;

    sget-object v3, Llyiahf/vczjk/x09;->OooO0oO:Llyiahf/vczjk/hc3;

    iget-object v3, v3, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v3}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/q45;->OooO0o0:Llyiahf/vczjk/i45;

    invoke-direct {v1, v2, v3, v4}, Llyiahf/vczjk/er5;-><init>(Llyiahf/vczjk/dn2;Llyiahf/vczjk/qt5;Llyiahf/vczjk/i45;)V

    sget-object v2, Llyiahf/vczjk/yk5;->OooOOo0:Llyiahf/vczjk/yk5;

    iput-object v2, v1, Llyiahf/vczjk/er5;->OooOo00:Llyiahf/vczjk/yk5;

    sget-object v2, Llyiahf/vczjk/r72;->OooO0o0:Llyiahf/vczjk/q72;

    const/4 v3, 0x0

    if-eqz v2, :cond_3

    iput-object v2, v1, Llyiahf/vczjk/er5;->OooOo0:Llyiahf/vczjk/q72;

    sget-object v2, Llyiahf/vczjk/cda;->OooOOO:Llyiahf/vczjk/cda;

    const-string v5, "T"

    invoke-static {v5}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-static {v1, v2, v5, v0, v4}, Llyiahf/vczjk/u4a;->o0000O(Llyiahf/vczjk/oo0o0Oo;Llyiahf/vczjk/cda;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/q45;)Llyiahf/vczjk/u4a;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    iget-object v2, v1, Llyiahf/vczjk/er5;->OooOo0o:Ljava/util/ArrayList;

    if-nez v2, :cond_2

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v2, v1, Llyiahf/vczjk/er5;->OooOo0o:Ljava/util/ArrayList;

    new-instance v0, Llyiahf/vczjk/sy0;

    iget-object v4, v1, Llyiahf/vczjk/er5;->OooOo:Ljava/util/ArrayList;

    iget-object v5, v1, Llyiahf/vczjk/er5;->OooOoO0:Llyiahf/vczjk/i45;

    invoke-direct {v0, v1, v2, v4, v5}, Llyiahf/vczjk/sy0;-><init>(Llyiahf/vczjk/yl5;Ljava/util/List;Ljava/util/Collection;Llyiahf/vczjk/q45;)V

    iput-object v0, v1, Llyiahf/vczjk/er5;->OooOo0O:Llyiahf/vczjk/sy0;

    sget-object v0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    if-eqz v0, :cond_1

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rf3;

    check-cast v2, Llyiahf/vczjk/ux0;

    invoke-virtual {v1}, Llyiahf/vczjk/oo0o0Oo;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v3

    iput-object v3, v2, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    goto :goto_0

    :cond_0
    sput-object v1, Llyiahf/vczjk/db9;->OooO00o:Llyiahf/vczjk/er5;

    return-void

    :cond_1
    const/16 v0, 0xd

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    throw v3

    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Type parameters are already set for "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1}, Llyiahf/vczjk/oo0o0Oo;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_3
    const/16 v0, 0x9

    invoke-static {v0}, Llyiahf/vczjk/er5;->o000oOoO(I)V

    throw v3
.end method
