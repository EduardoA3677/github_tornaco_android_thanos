.class public final Llyiahf/vczjk/r58;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/o58;


# static fields
.field public static final OooO0o0:Llyiahf/vczjk/era;


# instance fields
.field public final OooO00o:Ljava/util/Map;

.field public final OooO0O0:Llyiahf/vczjk/js5;

.field public OooO0OO:Llyiahf/vczjk/t58;

.field public final OooO0Oo:Llyiahf/vczjk/q58;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    sget-object v0, Llyiahf/vczjk/ye1;->OooOoo0:Llyiahf/vczjk/ye1;

    sget-object v1, Llyiahf/vczjk/x77;->OooOo0o:Llyiahf/vczjk/x77;

    sget-object v2, Llyiahf/vczjk/l68;->OooO00o:Llyiahf/vczjk/era;

    new-instance v2, Llyiahf/vczjk/era;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sput-object v2, Llyiahf/vczjk/r58;->OooO0o0:Llyiahf/vczjk/era;

    return-void
.end method

.method public constructor <init>(Ljava/util/Map;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/r58;->OooO00o:Ljava/util/Map;

    sget-object p1, Llyiahf/vczjk/y78;->OooO00o:[J

    new-instance p1, Llyiahf/vczjk/js5;

    invoke-direct {p1}, Llyiahf/vczjk/js5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/r58;->OooO0O0:Llyiahf/vczjk/js5;

    new-instance p1, Llyiahf/vczjk/q58;

    invoke-direct {p1, p0}, Llyiahf/vczjk/q58;-><init>(Llyiahf/vczjk/r58;)V

    iput-object p1, p0, Llyiahf/vczjk/r58;->OooO0Oo:Llyiahf/vczjk/q58;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/r58;->OooO0O0:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/js5;->OooOO0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/r58;->OooO00o:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 4

    check-cast p3, Llyiahf/vczjk/zf1;

    const v0, -0x47703d6d

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OoooOOO(Ljava/lang/Object;)V

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/r58;->OooO0Oo:Llyiahf/vczjk/q58;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/q58;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-eqz v2, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/r58;->OooO00o:Ljava/util/Map;

    invoke-interface {v2, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Map;

    sget-object v3, Llyiahf/vczjk/v58;->OooO00o:Llyiahf/vczjk/l39;

    new-instance v3, Llyiahf/vczjk/u58;

    invoke-direct {v3, v2, v0}, Llyiahf/vczjk/u58;-><init>(Ljava/util/Map;Llyiahf/vczjk/oe3;)V

    invoke-virtual {p3, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v0, v3

    goto :goto_0

    :cond_0
    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "Type of the key "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " is not supported. On Android you can only use types which can be stored inside the Bundle."

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_1
    :goto_0
    check-cast v0, Llyiahf/vczjk/t58;

    sget-object v2, Llyiahf/vczjk/v58;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/l39;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v2

    and-int/lit8 p4, p4, 0x70

    const/16 v3, 0x8

    or-int/2addr p4, v3

    invoke-static {v2, p2, p3, p4}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p4

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr p4, v2

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr p4, v2

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez p4, :cond_2

    if-ne v2, v1, :cond_3

    :cond_2
    new-instance v2, Llyiahf/vczjk/p58;

    invoke-direct {v2, p0, p1, v0}, Llyiahf/vczjk/p58;-><init>(Llyiahf/vczjk/r58;Ljava/lang/Object;Llyiahf/vczjk/t58;)V

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-static {p2, v2, p3}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    iget-boolean p1, p3, Llyiahf/vczjk/zf1;->OooOo:Z

    const/4 p2, 0x0

    if-eqz p1, :cond_4

    iget-object p1, p3, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    iget p1, p1, Llyiahf/vczjk/is8;->OooO:I

    iget p4, p3, Llyiahf/vczjk/zf1;->OooOoO0:I

    if-ne p1, p4, :cond_4

    const/4 p1, -0x1

    iput p1, p3, Llyiahf/vczjk/zf1;->OooOoO0:I

    iput-boolean p2, p3, Llyiahf/vczjk/zf1;->OooOo:Z

    :cond_4
    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-void
.end method
