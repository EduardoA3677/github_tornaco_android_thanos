.class public final Llyiahf/vczjk/sca;
.super Llyiahf/vczjk/tca;
.source "SourceFile"


# instance fields
.field public final OooOoOO:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rf3;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;Llyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct/range {p0 .. p11}, Llyiahf/vczjk/tca;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V

    move-object p1, p0

    invoke-static {p12}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p2

    iput-object p2, p1, Llyiahf/vczjk/sca;->OooOoOO:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final o0000O0(Llyiahf/vczjk/uf3;Llyiahf/vczjk/qt5;I)Llyiahf/vczjk/tca;
    .locals 13

    new-instance v0, Llyiahf/vczjk/sca;

    invoke-virtual {p0}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v4

    const-string v1, "<get-annotations>(...)"

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v6

    const-string v1, "getType(...)"

    invoke-static {v6, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/tca;->o0000O0O()Z

    move-result v7

    sget-object v11, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    new-instance v12, Llyiahf/vczjk/e19;

    const/4 v1, 0x4

    invoke-direct {v12, p0, v1}, Llyiahf/vczjk/e19;-><init>(Ljava/lang/Object;I)V

    iget-boolean v9, p0, Llyiahf/vczjk/tca;->OooOo:Z

    iget-object v10, p0, Llyiahf/vczjk/tca;->OooOoO0:Llyiahf/vczjk/uk4;

    const/4 v2, 0x0

    iget-boolean v8, p0, Llyiahf/vczjk/tca;->OooOo0o:Z

    move-object v1, p1

    move-object v5, p2

    move/from16 v3, p3

    invoke-direct/range {v0 .. v12}, Llyiahf/vczjk/sca;-><init>(Llyiahf/vczjk/rf3;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;Llyiahf/vczjk/le3;)V

    return-object v0
.end method
